package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	billingModel "github.com/amartyaa/repas/billing_microservice/billing/models"
	auditlogs "github.com/amartyaa/repas/common/audit_logs"
	azure "github.com/amartyaa/repas/common/azure"
	"github.com/amartyaa/repas/common/database"
	"github.com/amartyaa/repas/common/utils"
	"github.com/amartyaa/repas/internal/auth"
	user_models "github.com/amartyaa/repas/user_microservice/user/models"
	client_grpc "github.com/amartyaa/repas/workspace_microservice/grpc_client"
	"github.com/amartyaa/repas/workspace_microservice/workspace/models"
	"github.com/amartyaa/repas/workspace_microservice/workspace/queue"
	wsutils "github.com/amartyaa/repas/workspace_microservice/workspace/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// WorkspaceUpdateRequest is the request body for updating a workspace
type WorkspaceUpdateRequest struct {
	models.Workspace
	reqID            string
	TfConfig         map[string]interface{} `json:"tfconfig"`
	templateData     string
	templateType     string
	cpuTShirtSize    int
	memoryTShirtSize int
}

// UpdateHandler handles the update of a workspace
func (h *Handler) UpdateHandler(c *gin.Context) {
	reqID, _ := c.Get("request_id")
	email, _ := c.Get("email")
	wsID := c.Param("workspaceid")
	admin, _ := c.Get("DevOps_Lead")
	users, _ := c.Get("DevOps")
	ip := c.ClientIP()
	//Usertype, _ := c.Get("type")
	h.logger.Infof("Received Update Request %v for Workspace : %s  from %s", reqID, wsID, email)
	updtChan := make(chan error, 2)
	defer close(updtChan)
	apiResp := gin.H{
		"action":     "update",
		"body":       make(map[string]string, 0),
		"request_id": reqID,
	}
	eventChan := make(chan string)
	defer close(eventChan)

	request := new(WorkspaceUpdateRequest)
	ws := new(WorkspaceGetRequest)
	_ = ws.FetchWorkspace(h, wsID)
	if len(ws.m) == 0 {
		apiResp["error"] = "Workspace not found"
		apiResp["request_id"] = reqID
		h.logger.Errorf("Workspace not found")
		c.JSON(404, apiResp)
		return
	}
	err := c.BindJSON(&request)
	request.reqID = reqID.(string)
	if err != nil {
		apiResp["error"] = "Error in binding json"
		h.logger.Errorf("Error in binding json: %s", err)
		c.JSON(500, apiResp)
		return
	}
	// staticip is always system/Terraform-derived — never trust a client-supplied value on
	// update either. The CNV branch below already re-derives it from the DB; this just makes
	// that the only path for every template type, closing the same SSRF gap as create.go.
	// See docs/pentest/workspace_microservice-findings.md #3.
	delete(request.TfConfig, "staticip")

	if request.Project == "" {
		apiResp["error"] = "Project ID is missing in JSON"
		apiResp["request_id"] = reqID
		h.logger.Errorf("Project ID is missing in JSON")
		c.JSON(400, apiResp)
		return
	}

	// Deliberately checks the project claims only, not the platform-admin user
	// type: a platform admin who holds no role in this project has never been
	// able to update its workspaces, and this refactor does not change that.
	isProjectAdmin := auth.IsProjectMember(admin, request.Project)
	isProjectUser := auth.IsProjectMember(users, request.Project)
	if !isProjectAdmin && !isProjectUser {
		h.logger.Errorf("User is not a project admin for project: %s", request.Project)
		apiResp["error"] = "User is not a project admin for project"
		apiResp["request_id"] = reqID
		c.JSON(http.StatusForbidden, apiResp)

		return
	}

	if request.TfConfig == nil || reflect.TypeOf(request.TfConfig).Kind() != reflect.Map {
		apiResp["error"] = "TfConfig field is missing or not a valid map in JSON"
		apiResp["request_id"] = reqID
		h.logger.Errorf("TfConfig field is missing or not a valid map in JSON")
		c.JSON(400, apiResp)
		return
	}

	// Scheduler updates
	if request.StartCronExpression != ws.m[0].StartCronExpression || request.StopCronExpression != ws.m[0].StopCronExpression {
		apiResp["error"] = "Changing Scheduler Expression is not allowed in update, Use Schedule API for it"
		apiResp["request_id"] = reqID
		h.logger.Errorf("TfConfig field is missing or not a valid map in JSON")
		c.JSON(400, apiResp)
		return
	}

	request.TfConfig["vcol_environment"] = os.Getenv("APP_ENV")
	request.TfConfig["created_by"] = email.(string)
	var project user_models.Project
	cpu, _ := request.TfConfig["cpu"].(float64)
	memory, _ := request.TfConfig["memory"].(float64)
	drive, _ := request.TfConfig["drive"].(float64)
	platform, _ := request.TfConfig["platform"].(string)
	ides, _ := request.TfConfig["ides"].(string)
	h.logger.Infof("%d %d %d %s %s", int(cpu), int(memory), int(drive), platform, ides)

	request.templateData, request.templateType, err = GetTemplateDataByTemplateID(h.dbStore, request.TemplateID)
	if err != nil {
		apiResp["error"] = "Error in reading template data"
		apiResp["request_id"] = reqID
		h.logger.Errorf("Error in reading template data: %s", err)
		return
	}
	if request.TShirtSize != "TX" {
		request.cpuTShirtSize, request.memoryTShirtSize, err = GetTShirtSizeBySizeCode(h.dbStore, request.TShirtSize)
		if err != nil {
			h.logger.Errorf("Error fetching tshirt size for selected size code: %s", err)
			apiResp["error"] = "Error fetching tshirt size for selected size code"
			c.JSON(500, apiResp)
			return
		}
		cpu = float64(request.cpuTShirtSize)
		memory = float64(request.memoryTShirtSize)
	}

	// Downgrade protection: CPU, memory and drive can only stay the same or increase.
	currentCPU, currentMemory, currentDrive, err := h.GetCurrentWorkspaceSizesForUpdate(request.Project, wsID)
	if err != nil {
		if err == sql.ErrNoRows {
			apiResp["error"] = "Current workspace resource sizes not found"
			apiResp["request_id"] = reqID
			h.logger.Errorf("Current resource sizes not found for workspace %s in project %s", wsID, request.Project)
			c.JSON(http.StatusNotFound, apiResp)
			return
		}
		apiResp["error"] = "Error getting current workspace resource sizes"
		apiResp["request_id"] = reqID
		h.logger.Errorf("Error getting current resource sizes for workspace %s: %s", wsID, err)
		c.JSON(http.StatusInternalServerError, apiResp)
		return
	}

	h.logger.Infof("Workspace resource update comparison - Workspace: %s, Current CPU: %.2f, Requested CPU: %.2f, Current Memory: %.2f, Requested Memory: %.2f, Current Drive: %.2f, Requested Drive: %.2f",
		wsID, currentCPU, cpu, currentMemory, memory, currentDrive, drive)

	if cpu < currentCPU {
		apiResp["error"] = fmt.Sprintf("CPU downgrade is not allowed. Current CPU is %.2f and requested CPU is %.2f", currentCPU, cpu)
		apiResp["request_id"] = reqID
		h.logger.Errorf("CPU downgrade rejected for workspace %s: current CPU %.2f, requested CPU %.2f", wsID, currentCPU, cpu)
		c.JSON(http.StatusBadRequest, apiResp)
		return
	}

	if memory < currentMemory {
		apiResp["error"] = fmt.Sprintf("Memory downgrade is not allowed. Current memory is %.2f and requested memory is %.2f", currentMemory, memory)
		apiResp["request_id"] = reqID
		h.logger.Errorf("Memory downgrade rejected for workspace %s: current memory %.2f, requested memory %.2f", wsID, currentMemory, memory)
		c.JSON(http.StatusBadRequest, apiResp)
		return
	}

	if drive < currentDrive {
		apiResp["error"] = fmt.Sprintf("Drive downgrade is not allowed. Current drive is %.2f and requested drive is %.2f", currentDrive, drive)
		apiResp["request_id"] = reqID
		h.logger.Errorf("Drive downgrade rejected for workspace %s: current drive %.2f, requested drive %.2f", wsID, currentDrive, drive)
		c.JSON(http.StatusBadRequest, apiResp)
		return
	}

	logEvent := &billingModel.AuditLog{
		ID:                uuid.MustParse(reqID.(string)),
		ResourceType:      "Workspace",
		Action:            "Update",
		ProjectID:         request.Project,
		ActionPerformedBy: email.(string),
		ResourceID:        request.ID,
		ActionDoneAt:      time.Now().Format("2006-01-02 15:04:05.000000-07"),
		Comments:          "",
		IP:                ip,
	}
	auditlogs.CreateEvent(h.dbStore, logEvent)
	if request.templateType == "IDE" || request.templateType == "Linux_VDI" {
		// Get the existing workspace sizes
		existingCPUSum, existingMemorySum, existingDriveSum, err := h.GetExistingWorkspaceSizesForUpdate(request.Project, wsID)
		if err != nil {
			apiResp["error"] = "Error getting existing workspace sizes"
			apiResp["request_id"] = reqID
			h.logger.Errorf("Error getting existing workspace sizes: %s", err)
			c.JSON(500, apiResp)
			return
		}

		totalCPUSum := existingCPUSum + cpu
		totalMemorySum := existingMemorySum + memory
		totalDriveSum := existingDriveSum + drive

		h.logger.Infof("Total CPU Size: %f, Total Memory Size: %f, Total Drive Size: %f", totalCPUSum, totalMemorySum, totalDriveSum)
		project.CPUQuota, project.MemoryQuota, project.StorageQuota, project.VDICPUQuota, project.VDIMemoryQuota, project.VDIStorageQuota, err = h.GetProjectSizes(request.Project)
		if err != nil {
			apiResp["error"] = "Error getting project sizes"
			apiResp["request_id"] = reqID
			h.logger.Errorf("Error getting project sizes: %s", err)
			c.JSON(500, apiResp)
			return
		}
		// Check if totalCPUSum exceeds default size
		if totalCPUSum > float64(project.CPUQuota) {
			h.logger.Errorf("Limit has been exceeded for Core CPU. Please contact the platform admin.")
			apiResp["error"] = "Limit has been exceeded Core CPU. Please contact the platform admin."
			apiResp["request_id"] = reqID
			c.JSON(http.StatusForbidden, apiResp)
			return
		}
		// Check if totalMemorySum exceeds default size
		if totalMemorySum > float64(project.MemoryQuota) {
			h.logger.Errorf("Limit has been exceeded for Memory. Please contact the platform admin.")
			apiResp["error"] = "Limit has been exceeded for Memory. Please contact the platform admin."
			apiResp["request_id"] = reqID
			c.JSON(http.StatusForbidden, apiResp)
			return
		}
		// Check if totalDriveSum exceeds default size
		if totalDriveSum > float64(project.StorageQuota) {
			h.logger.Errorf("Limit has been exceeded for Drive. Please contact the platform admin.")
			apiResp["error"] = "Limit has been exceeded for Drive. Please contact the platform admin."
			apiResp["request_id"] = reqID
			c.JSON(http.StatusForbidden, apiResp)
			return
		}
	}

	if request.templateType == "Linux_CNV" || request.templateType == "Windows_CNV" || request.templateType == "Azure_Linux_VM" || request.templateType == "Azure_Windows_VM" {

		if request.TShirtSize == "TX" {
			if cpu < 1 || float64(int(cpu)) != cpu {
				apiResp["error"] = "CPU size should be a Natural Number"
				apiResp["request_id"] = reqID
				h.logger.Errorf("CPU size should be a Natural Number")
				c.JSON(400, apiResp)
				return
			}
			if memory < 1 || float64(int(memory)) != memory {
				apiResp["error"] = " Memory size should be a Natural Number"
				apiResp["request_id"] = reqID
				h.logger.Errorf("Memory size should be a Natural Number")
				c.JSON(400, apiResp)
				return
			}
		} else {
			request.cpuTShirtSize, request.memoryTShirtSize, err = GetTShirtSizeBySizeCode(h.dbStore, request.TShirtSize)
			if err != nil {
				h.logger.Errorf("Error fetching tshirt size for selected size code: %s", err)
				apiResp["error"] = "Error fetching tshirt size for selected size code"
				c.JSON(500, apiResp)
				return
			}
			cpu = float64(request.cpuTShirtSize)
			memory = float64(request.memoryTShirtSize)
		}

		// Get the existing workspace sizes
		existingCNVCPUSum, existingCNVMemorySum, existingCNVDriveSum, err := h.GetExistingCNVWorkspaceSizesForUpdate(request.Project, wsID)
		if err != nil {
			apiResp["error"] = "Error getting existing workspace sizes"
			apiResp["request_id"] = reqID
			h.logger.Errorf("Error getting existing workspace sizes: %s", err)
			c.JSON(500, apiResp)
			return
		}

		totalCNVCPUSum := existingCNVCPUSum + cpu
		totalCNVMemorySum := existingCNVMemorySum + memory
		totalCNVDriveSum := existingCNVDriveSum + drive

		h.logger.Infof("Total CPU Size: %f, Total Memory Size: %f, Total Drive Size: %f", totalCNVCPUSum, totalCNVMemorySum, totalCNVDriveSum)
		project.CPUQuota, project.MemoryQuota, project.StorageQuota, project.VDICPUQuota, project.VDIMemoryQuota, project.VDIStorageQuota, err = h.GetProjectSizes(request.Project)
		if err != nil {
			apiResp["error"] = "Error getting project sizes"
			apiResp["request_id"] = reqID
			h.logger.Errorf("Error getting project sizes: %s", err)
			c.JSON(500, apiResp)
			return
		}
		// Check if totalCNVCPUSum exceeds default size
		if totalCNVCPUSum > float64(project.VDICPUQuota) {
			h.logger.Errorf("Limit has been exceeded for Core CPU. Please contact the platform admin.")
			apiResp["error"] = "Limit has been exceeded Core CPU. Please contact the platform admin."
			apiResp["request_id"] = reqID
			c.JSON(http.StatusForbidden, apiResp)
			return
		}
		// Check if totalCNVMemorySum exceeds default size
		if totalCNVMemorySum > float64(project.VDIMemoryQuota) {
			h.logger.Errorf("Limit has been exceeded for Memory. Please contact the platform admin.")
			apiResp["error"] = "Limit has been exceeded for Memory. Please contact the platform admin."
			apiResp["request_id"] = reqID
			c.JSON(http.StatusForbidden, apiResp)
			return
		}
		// Check if totalCNVDriveSum exceeds default size
		if totalCNVDriveSum > float64(project.VDIStorageQuota) {
			h.logger.Errorf("Limit has been exceeded for Drive. Please contact the platform admin.")
			apiResp["error"] = "Limit has been exceeded for Drive. Please contact the platform admin."
			apiResp["request_id"] = reqID
			c.JSON(http.StatusForbidden, apiResp)
			return
		}
	}

	if request.templateType == "Linux_CNV" || request.templateType == "Windows_CNV" {
		workspaceIP, err := fetchStaticIPFromDB(h, request.ID)
		if err != nil {
			apiResp["error"] = "Error fetching static IP from workspace table"
			apiResp["request_id"] = reqID
			h.logger.Errorf("Error fetching static IP from workspace table: %v", err)
			c.JSON(500, apiResp)
			return
		}

		if newIP, exists := request.TfConfig["staticip"]; !exists {
			request.TfConfig["staticip"] = workspaceIP
		} else {
			if workspaceIP != newIP {
				apiResp["error"] = "Static IP cannot be changed"
				apiResp["request_id"] = reqID
				h.logger.Errorf("Static IP cannot be changed")
				c.JSON(400, apiResp)
				return
			}
		}
		image := tfConfigString(request.TfConfig, "image")
		if strings.HasPrefix(image, "vcollab-default-image-") {
			size, err := GetdefaultCNVImages(image)
			if err != nil {
				h.logger.Errorf("Error fetching default CNV size: %s", err)
				apiResp["error"] = "Error fetching default CNV size"
				apiResp["request_id"] = reqID
				c.JSON(500, apiResp)
				return
			}
			sizeFloat, _ := strconv.ParseFloat(size, 64)
			if sizeFloat > drive {
				h.logger.Errorf("Drive size should be greater than %s", size)
				apiResp["error"] = "Drive size should be greater than " + size
				apiResp["request_id"] = reqID
				c.JSON(400, apiResp)
				return
			}
		} else {
			size, err := GetCustomCNVSize(h.dbStore, image)
			if err != nil {
				h.logger.Errorf("Error fetching custom CNV size: %s", err)
				apiResp["error"] = "Error fetching custom CNV size"
				apiResp["request_id"] = reqID
				c.JSON(500, apiResp)
				return
			}
			SizeFloat, _ := strconv.ParseFloat(size, 64)

			driveSize, err := GetExistingWorkspaceDriveSize(h.dbStore, wsID)
			if err != nil {
				apiResp["error"] = "Error getting existing workspace drive size"
				apiResp["request_id"] = reqID
				h.logger.Errorf("Error getting existing workspace drive size: %s", err)
				c.JSON(500, apiResp)
				return
			}
			sizeFloat, _ := strconv.ParseFloat(driveSize, 64)

			if sizeFloat > drive || SizeFloat > drive {
				apiResp["error"] = "Drive size cannot be less than workspace drive size " + driveSize + " and custom CNV size " + size
				apiResp["request_id"] = reqID
				h.logger.Errorf("Drive size cannot be less than workspace drive size %s", driveSize, " and custom CNV size %s", size)
				c.JSON(400, apiResp)
				return
			}
		}
	}

	if request.templateType == "Azure_Linux_VM" || request.templateType == "Azure_Windows_VM" {
		// Fetch size from image
		size, err := azure.GetImageSizeByID(context.TODO(), tfConfigString(request.TfConfig, "image"))
		if err != nil {
			h.logger.Errorf("Error fetching image size: %s", err)
			apiResp["error"] = "Invalid image ID provided"
			apiResp["request_id"] = reqID
			c.JSON(http.StatusBadRequest, apiResp)
			return
		}
		sizeFloat, _ := strconv.ParseFloat(size, 64)
		if sizeFloat > drive {
			h.logger.Errorf("Drive size should be greater than %s", size)
			apiResp["error"] = "Drive size should be greater than " + size
			apiResp["request_id"] = reqID
			c.JSON(400, apiResp)
			return
		}

		driveSize, err := GetExistingWorkspaceDriveSize(h.dbStore, wsID)
		if err != nil {
			apiResp["error"] = "Error getting existing workspace drive size"
			apiResp["request_id"] = reqID
			h.logger.Errorf("Error getting existing workspace drive size: %s", err)
			c.JSON(500, apiResp)
			return
		}
		SizeFloat, _ := strconv.ParseFloat(driveSize, 64)

		if sizeFloat > drive || SizeFloat > drive {
			apiResp["error"] = "Drive size cannot be less than workspace drive size " + driveSize + " and custom VM size " + size
			apiResp["request_id"] = reqID
			h.logger.Errorf("Drive size cannot be less than workspace drive size %s", driveSize, " and custom VM size %s", size)
			c.JSON(400, apiResp)
			return
		}
	}

	if ws.m[0].CreatedBy == email.(string) {
		request.ID = wsID
		request.UpdatedBy.String = email.(string)
		request.UpdatedAt = time.Unix(time.Now().Unix(), 0)
		request.OperationName = "UPDATION"
		request.OperationStatus = "IN-PROGRESS"
		request.TfConfig["project"] = request.Project
		request.TfConfig["name"] = request.ID
		request.TfConfig["vcol_environment"] = os.Getenv("APP_ENV")
		request.TfConfig["created_by"] = utils.ConvertStringToRFC1123(email.(string))
		if request.TShirtSize != "TX" {
			request.TfConfig["cpu"] = float64(request.cpuTShirtSize)
			request.TfConfig["memory"] = float64(request.memoryTShirtSize)
		}
		if os.Getenv("PLATFORM") == "azure" {
			setAzureArtifactTfConfig(request.TfConfig, request.templateType)
		}
		if request.templateType == "IDE" || request.templateType == "Linux_VDI" {
			imageRef, ok := request.TfConfig["image"].(string)
			if !ok || imageRef == "" {
				h.logger.Errorf("Missing or invalid image for workspace %s", wsID)
				apiResp["error"] = "image is required for this template type"
				apiResp["request_id"] = reqID
				c.JSON(http.StatusBadRequest, apiResp)
				return
			}
			resolvedImage, err := resolveImageDigest(imageRef)
			if err != nil {
				h.logger.Errorf("Error resolving image digest for %s: %s", imageRef, err)
				apiResp["error"] = "Unable to resolve image digest from Harbor"
				apiResp["request_id"] = reqID
				c.JSON(http.StatusBadRequest, apiResp)
				return
			}
			request.TfConfig["image"] = resolvedImage
		}
		if request.templateType == "Azure_Linux_VM" || request.templateType == "Azure_Windows_VM" {
			image, err := GetExistingWorkspaceImage(h.dbStore, wsID)
			if err != nil {
				apiResp["error"] = "Error getting existing workspace image"
				apiResp["request_id"] = reqID
				h.logger.Errorf("Error getting existing workspace image: %s", err)
				c.JSON(500, apiResp)
				return
			}
			request.TfConfig["image"] = image
			shape, err := GetAzureShapeBySizeCode(h.dbStore, request.TShirtSize)
			if err != nil {
				h.logger.Errorf("Error fetching azure shapes for selected size code: %s", err)
				apiResp["error"] = "Error fetching azure shapes for selected size code"
				c.JSON(500, apiResp)
				return
			}
			request.TfConfig["size"] = shape
		}

		// Invalidate cache entry for this workspace
		models.GlobalCache.Delete(wsID)

		apiResp["message"] = "Workspace updation initiated"
		apiResp["body"] = request
		c.JSON(http.StatusAccepted, apiResp)

		go func(request WorkspaceUpdateRequest, email string, reqID string) {
			var res string
			var err1 error
			var output any

			defer func() {
				logs := inmemoryQueue.GetLogs(request.ID)
				var allLogs string
				for _, logEntry := range logs {
					allLogs += logEntry.Message + "\n"
				}
				if errUpd := h.updateWorkspaceLogs(request.ID, reqID, allLogs, "UPDATION"); errUpd != nil {
					h.logger.Errorf("Failed to update logs in DB for workspace %s: %v", request.ID, errUpd)
				}
			}()

			res, output, err1 = request.updateProvision(inmemoryQueue)
			h.logger.Infof("Response while Updating Workspace: %s", res)
			h.logger.Infof("Output: %v", output)
			if output == nil {
				output = "{}"
			}
			h.dbStore.Exec(`UPDATE workspace SET OUTPUT = $1 WHERE id = $2`, output, request.ID)
			if err1 != nil || res == "FAILED" {
				h.logger.Errorf("Error while Updating Workspace: %s", err)
				request.OperationStatus = "FAILED"
				request.updatestatus(h)
			}
			if res == "SUCCESS" {
				request.OperationStatus = "SUCCESS"
				request.UpdateWorkspace(h)
				request.updatestatus(h)
				h.logger.Infof("Workspace updated successfully in the database for ID: %s", request.ID)
			}
			h.logger.Debugw("Provisioner finished", "request_id", reqID)
			if res == "FAILED" {
				request.OperationStatus = "FAILED"
				request.updatestatus(h)
				h.logger.Debugf("Provisioner failed while updating workspace %s: %s request_id", request.ID, reqID)
			}

			// Retrieve the Terraform state data from the states table
			stateName := fmt.Sprintf("%s_%s", request.Project, request.ID)
			h.logger.Infof("Constructed stateName: %s", stateName)
			var stateData string
			query := `SELECT data FROM terraform_remote_state.states WHERE name = $1`
			err = h.dbStore.GetDB().QueryRow(query, stateName).Scan(&stateData)
			if err != nil {
				h.logger.Errorf("Failed to retrieve state data from states table for workspace %s: %s", request.ID, err)
			}
			h.logger.Debugf("Retrieved stateData: %s", stateData)
			// Extract resources from the state data
			var stateResources []string
			err = extractResourcesFromState([]byte(stateData), &stateResources)
			if err != nil {
				h.logger.Errorf("Failed to extract resources from state data: %s", err)
			} else {
				h.logger.Infof("Extracted resources: %v", stateResources)

				// Store the extracted resources in the resources column of the workspace table
				stateResourcesJSON, _ := json.Marshal(stateResources)
				_, err = h.dbStore.Exec(
					`UPDATE workspace SET resources = $1 WHERE id = $2`, string(stateResourcesJSON), request.ID,
				)
				if err != nil {
					h.logger.Errorf("Failed to update resources column in workspace table: %s", err)
				} else {
					h.logger.Infof("Successfully updated resources column for workspace ID: %s", request.ID)
				}
			}
			// Extract private_ip from the state data for Azure_Linux_VM or Azure_Windows_VM
			if request.templateType == "Azure_Linux_VM" || request.templateType == "Azure_Windows_VM" {
				var stateJSON struct {
					Resources []struct {
						Type      string `json:"type"`
						Name      string `json:"name"`
						Instances []struct {
							Attributes struct {
								PrivateIPAddress string `json:"private_ip_address"`
							} `json:"attributes"`
						} `json:"instances"`
					} `json:"resources"`
				}

				// Parse the state data to extract private_ip
				err = json.Unmarshal([]byte(stateData), &stateJSON)
				if err != nil {
					h.logger.Errorf("Failed to parse state data for workspace %s: %s", request.ID, err)
					return
				}

				var privateIP string
				for _, res := range stateJSON.Resources {
					// Handle both Linux and Windows VM resource types
					if res.Type == "azurerm_linux_virtual_machine" || res.Type == "azurerm_windows_virtual_machine" {
						if len(res.Instances) > 0 {
							privateIP = res.Instances[0].Attributes.PrivateIPAddress
							break
						}
					}
				}

				if privateIP == "" {
					h.logger.Warnf("No private_ip found in state data for workspace %s", request.ID)
					return
				}

				h.logger.Infof("Extracted private_ip: %s", privateIP)

				// Update the workspace table with the static IP
				_, err = h.dbStore.Exec(
					`UPDATE workspace SET tfconfig = jsonb_set(tfconfig, '{staticip}', $1::jsonb) WHERE id = $2`,
					fmt.Sprintf(`"%s"`, privateIP), request.ID,
				)
				if err != nil {
					h.logger.Errorf("Failed to update tfconfig column in workspace table with staticip: %s", err)
				} else {
					h.logger.Infof("Successfully updated tfconfig column with staticip for workspace ID: %s", request.ID)
				}
			}

			var workspaceEntry billingModel.WorkspaceAction
			var count int

			// Check if there is a "start" action for the given workspace
			h.logger.Infof("Checking if there is a 'start' action for workspace_name: %s, project_id: %s", wsID, request.Project)
			errmp := h.dbStore.GetDB().QueryRow("SELECT COUNT(*) FROM workspace_action WHERE workspace_name = $1 AND project_id = $2 AND action = $3", wsID, request.Project, "start").Scan(&count)
			if errmp != nil {
				h.logger.Errorf("Error in checking workspace_action data: %s", errmp)
				apiResp["error"] = "Error in checking workspace_action data"
				apiResp["request_id"] = reqID
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error in checking workspace_action data"})
				return
			}
			h.logger.Infof("Count of 'start' actions: %d", count)

			// If there is already a "start" action, do not insert new entries
			if count > 0 {
				h.logger.Infof("workspace updated successfully")
				return
			}
			err := h.dbStore.GetDB().QueryRow("SELECT id, workspace_name, project_id, action, started_at FROM workspace_action WHERE workspace_name = $1 AND project_id = $2 AND action = $3", wsID, request.Project, "stop").Scan(
				&workspaceEntry.ID, &workspaceEntry.WorkspaceName, &workspaceEntry.ProjectID, &workspaceEntry.Action, &workspaceEntry.StartedAt)
			if err != nil {
				if err == sql.ErrNoRows {
					h.logger.Warnf("No 'stop' action found for workspace_name: %s, project_id: %s", wsID, request.Project)
				} else {
					h.logger.Errorf("Error in fetching workspace_action data: %s", err)
					apiResp["error"] = "Error in fetching workspace_action data"
					apiResp["request_id"] = reqID
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Error in fetching workspace_action data"})
					return
				}
			}
			// Insert new "start" action and billing data
			startTime := time.Now().Format("2006-01-02 15:04:05.000000-07")
			StartTime, _ := time.Parse("2006-01-02 15:04:05.000000-07", startTime)
			err = wsutils.InsertIntoWorkspaceActionTable(request.ID, request.Project, "start", email, StartTime, h.dbStore)
			if err != nil {
				h.logger.Errorf("Error while inserting in workspace_action data: %s", err)
				apiResp["error"] = "Error while inserting in workspace_action data"
				apiResp["request_id"] = reqID
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while inserting in workspace_action data"})
				return
			}
			err = wsutils.InsertIntoCPUBillingTable(request.ID, request.Project, "start", email, StartTime, tfConfigInt(request.TfConfig, "cpu"), h.dbStore)
			if err != nil {
				h.logger.Errorf("Error while inserting in CPUBilling data: %s", err)
				apiResp["error"] = "Error while inserting in CPUBilling data"
				apiResp["request_id"] = reqID
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while inserting in CPUBilling data"})
				return
			}
			err = wsutils.InsertIntoMemoryBillingTable(request.ID, request.Project, "start", email, StartTime, tfConfigInt(request.TfConfig, "memory"), h.dbStore)
			if err != nil {
				h.logger.Errorf("Error while inserting in MemoryBilling data: %s", err)
				apiResp["error"] = "Error while inserting in MemoryBilling data"
				apiResp["request_id"] = reqID
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while inserting in MemoryBilling data"})
				return
			}
		}(*request, email.(string), reqID.(string))
	}
}

// UpdateWorkspace updates the workspace in the database
func (w *WorkspaceUpdateRequest) UpdateWorkspace(h *Handler) error {
	h.logger.Infof("Updating Workspace %s with updated_by %s", w.ID, w.UpdatedBy.String)
	tfconfigJSON, err := json.Marshal(w.TfConfig)
	if err != nil {
		return err
	}
	projectName := w.Project
	var actualProjectID string
	rows, err := h.dbStore.Query("SELECT id FROM projects WHERE name=$1", projectName)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&actualProjectID)
		if err != nil {
			return err
		}
	}
	_, err = h.dbStore.Exec(`
		UPDATE workspace SET 
		updated_at = $1, updated_by = $2, tshirt_size = $3, tfconfig = $4,
		operation_name = $5, operation_status = $6, start_cron_expression = $7, stop_cron_expression = $8
		WHERE id = $9`, w.UpdatedAt, w.UpdatedBy.String, w.TShirtSize, tfconfigJSON, w.OperationName, w.OperationStatus, w.StartCronExpression, w.StopCronExpression, w.ID)
	return err
}

func (w *WorkspaceUpdateRequest) updateProvision(queue *queue.ProvisionQueue) (string, any, error) {
	port := os.Getenv("PROVISIONER_PORT")
	if port == "" {
		port = ":50051"
	}
	host := os.Getenv("PROVISIONER_HOST")
	if host == "" {
		host = "localhost"
	}

	client, err := client_grpc.GetClient(host, port)
	if err != nil {
		return "", nil, err
	}

	// TODO: Save the output later to DB
	//var output interface{}
	return client.ProvisionerMethod(w.reqID, w.ID, w.Project, w.TfConfig, w.templateData, "APPLY", queue)

}

// GetExistingWorkspaceImage returns the image value from tfconfig for a given workspace
func GetExistingWorkspaceImage(db *database.PostgresDB, workspaceID string) (string, error) {
	var image string
	err := db.GetDB().QueryRow("SELECT tfconfig->>'image' FROM workspace WHERE id = $1", workspaceID).Scan(&image)
	if err != nil {
		return "", err
	}

	return image, nil
}

// GetExistingWorkspaceDriveSize returns the existing workspace drive size
func GetExistingWorkspaceDriveSize(db *database.PostgresDB, workspaceID string) (string, error) {
	var drive string
	err := db.GetDB().QueryRow("SELECT tfconfig->>'drive' FROM workspace WHERE id = $1", workspaceID).Scan(&drive)
	if err != nil {
		return "", err
	}
	return drive, nil
}

// GetExistingWorkspaceSizesForUpdate calculates existing resource usage
// excluding the workspace currently being updated.
func (h *Handler) GetExistingWorkspaceSizesForUpdate(
	projectID string,
	workspaceID string,
) (cpuSum, memorySum, driveSum float64, err error) {
	rows, err := h.dbStore.Query(`
		SELECT tfconfig->>'cpu', tfconfig->>'memory', tfconfig->>'drive'
		FROM workspace
		WHERE project_id = $1
		  AND id != $2
		  AND type IN ('Linux_VDI', 'IDE')
		  AND (
			(operation_name != 'DELETION')
			OR
			(operation_name = 'DELETION' AND operation_status != 'SUCCESS')
		  )`,
		projectID,
		workspaceID,
	)
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var cpu, memory, drive sql.NullFloat64
		err := rows.Scan(&cpu, &memory, &drive)
		if err != nil {
			return 0, 0, 0, err
		}
		if cpu.Valid {
			cpuSum += cpu.Float64
		}
		if memory.Valid {
			memorySum += memory.Float64
		}
		if drive.Valid {
			driveSum += drive.Float64
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, err
	}
	return cpuSum, memorySum, driveSum, nil
}

// GetExistingCNVWorkspaceSizesForUpdate calculates the sum of CPU, memory,
// and drive sizes of existing CNV workspaces, excluding the workspace being updated.
func (h *Handler) GetExistingCNVWorkspaceSizesForUpdate(
	projectID string,
	workspaceID string,
) (cnvCPUSum, cnvMemorySum, cnvDriveSum float64, err error) {
	rows, err := h.dbStore.Query(`
		SELECT tfconfig->>'cpu', tfconfig->>'memory', tfconfig->>'drive'
		FROM workspace
		WHERE project_id = $1
		  AND id != $2
		  AND type IN ('Linux_CNV', 'Windows_CNV', 'Azure_Linux_VM', 'Azure_Windows_VM')
		  AND ((operation_name != 'DELETION')
		  OR (operation_name = 'DELETION' AND operation_status != 'SUCCESS'))`,
		projectID,
		workspaceID)
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var cpu, memory, drive sql.NullFloat64
		err := rows.Scan(&cpu, &memory, &drive)
		if err != nil {
			return 0, 0, 0, err
		}
		if cpu.Valid {
			cnvCPUSum += cpu.Float64
		}
		if memory.Valid {
			cnvMemorySum += memory.Float64
		}
		if drive.Valid {
			cnvDriveSum += drive.Float64
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, err
	}
	return cnvCPUSum, cnvMemorySum, cnvDriveSum, nil
}

func (w *WorkspaceUpdateRequest) updatestatus(h *Handler) error {
	h.logger.Infof("Updating Workspace %s with created_by %s", w.ID, w.CreatedBy)
	_, err := h.dbStore.Exec(`
	UPDATE workspace SET 
	operation_name = $1, operation_status = $2
	WHERE id = $3`, w.OperationName, w.OperationStatus, w.ID)
	return err
}

func fetchStaticIPFromDB(h *Handler, workspaceID string) (string, error) {
	var staticIP string
	rows, err := h.dbStore.Query("SELECT tfconfig->>'staticip' FROM workspace WHERE id = $1", workspaceID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&staticIP)
		if err != nil {
			return "", err
		}
	}
	return staticIP, nil
}

// GetCurrentWorkspaceSizesForUpdate returns the currently stored cpu, memory and
// drive of the workspace being updated. Used to block size downgrades.
func (h *Handler) GetCurrentWorkspaceSizesForUpdate(
	projectID string,
	workspaceID string,
) (cpuCurrent, memoryCurrent, driveCurrent float64, err error) {
	err = h.dbStore.GetDB().QueryRow(`
		SELECT
			COALESCE(NULLIF(tfconfig->>'cpu', '')::double precision, 0),
			COALESCE(NULLIF(tfconfig->>'memory', '')::double precision, 0),
			COALESCE(NULLIF(tfconfig->>'drive', '')::double precision, 0)
		FROM workspace
		WHERE project_id = $1
		AND id = $2`,
		projectID,
		workspaceID,
	).Scan(
		&cpuCurrent,
		&memoryCurrent,
		&driveCurrent,
	)
	if err != nil {
		return 0, 0, 0, err
	}

	return cpuCurrent, memoryCurrent, driveCurrent, nil
}
