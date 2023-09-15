package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"vls-api/models"
	"vls-api/utils"

	"github.com/gin-gonic/gin"
)

func GetVulnerability(c *gin.Context) {

	var vlsResponse models.ScanResponse
	var inputRequest models.ScanRequests
	var myCache utils.Cache

	if err := c.BindJSON(&inputRequest); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	for _, req := range inputRequest.ScanRequest {
		PayloadForVersion := models.PayloadForNoVersion{
			Package: models.InputWithoutVersion{
				Name:      req.Name,
				Ecosystem: req.Ecosystem,
			},
		}

		if req.Ecosystem == "PyPI" {
			query := PayloadForVersion
			scanResponse := models.ScanResults{}
			scanResponse.PackageName = req.Name
			scanResponse.VulnerableVersions = make(map[string]models.Version)

			source := "osv"
			cacheKey := source + "-" + query.Package.Ecosystem + "-" + query.Package.Name

			if result, ok := myCache.Get(cacheKey); ok {
				fmt.Println("Results from Cache")
				scanResponse.PackageName = result.PackageName
				scanResponse.VulnerableVersions = result.VulnerableVersions
				vlsResponse.ScanResults = append(vlsResponse.ScanResults, scanResponse)
			} else {

				payloadBytes, err := json.Marshal(query)
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error while Marshaling JSON",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(payloadBytes))
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error Sending Request:",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error while Reading Response",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				var osvResponse models.OsvResponse
				err = json.Unmarshal(body, &osvResponse)
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error While Reading Response",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				for _, vuln := range osvResponse.Vulns {
					for _, affected := range vuln.Affected {
						if affected.Package.Name == req.Name && affected.Package.Ecosystem == req.Ecosystem {
							for _, version := range affected.Versions {

								if ver, ok := scanResponse.VulnerableVersions[version]; ok {
									vulnerability := models.Vulnerability{
										Summary:  vuln.Summary,
										Details:  vuln.Details,
										Severity: vuln.DatabaseSpecific.Severity,
									}
									ver.Vulnerabilities = append(ver.Vulnerabilities, vulnerability)
									ver.OverallSeverity = getOverallSeverity(ver.OverallSeverity, vulnerability.Severity)

									scanResponse.VulnerableVersions[version] = ver
								} else {

									vulnerablities := []models.Vulnerability{
										{
											Summary:  vuln.Summary,
											Details:  vuln.Details,
											Severity: vuln.DatabaseSpecific.Severity,
										},
									}
									versionInfo := models.Version{
										Vulnerabilities: vulnerablities,
										OverallSeverity: vuln.DatabaseSpecific.Severity,
									}
									scanResponse.VulnerableVersions[version] = versionInfo
								}
							}
						}
					}
				}

				if req.Version != "" {
					for version := range scanResponse.VulnerableVersions {
						if version != req.Version {
							delete(scanResponse.VulnerableVersions, version)
						}
					}
				}
				vlsResponse.ScanResults = append(vlsResponse.ScanResults, scanResponse)
				myCache.Set(cacheKey, scanResponse, 2*time.Hour)
			}
		} else if req.Ecosystem == "npm" || req.Ecosystem == "crates.io" || req.Ecosystem == "Go" || req.Ecosystem == "Maven" {
			query := PayloadForVersion
			scanResponse := models.ScanResults{}
			scanResponse.PackageName = req.Name
			scanResponse.VulnerableVersions = make(map[string]models.Version)

			source := "osv"
			cacheKey := source + "-" + query.Package.Ecosystem + "-" + query.Package.Name

			if result, ok := myCache.Get(cacheKey); ok {
				fmt.Println("Results from Cache")

				scanResponse.PackageName = result.PackageName
				scanResponse.VulnerableVersions = result.VulnerableVersions
				vlsResponse.ScanResults = append(vlsResponse.ScanResults, scanResponse)
			} else {

				payloadBytes, err := json.Marshal(query)
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error while Marshaling JSON",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(payloadBytes))
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error Sending Request:",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error while Reading Response",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				var osvResponseNpm models.OsvResponseNPM
				err = json.Unmarshal(body, &osvResponseNpm)
				if err != nil {
					errorMessage := models.ErrorResponse{
						Message: "Error while Unmarshalling Response",
					}
					c.PureJSON(500, errorMessage)
					return
				}

				for _, vuln := range osvResponseNpm.Vulns {
					for _, affectedPackage := range vuln.Affected {
						if affectedPackage.Package.Name == req.Name {
							for _, affectedRange := range affectedPackage.Ranges {
								if affectedRange.Type == "SEMVER" || affectedRange.Type == "ECOSYSTEM" {
									for _, event := range affectedRange.Events {
										introduced := event.Introduced
										if introduced == "" {
											continue
										}
										if ver, ok := scanResponse.VulnerableVersions[introduced]; ok {
											vulnerability := models.Vulnerability{
												Summary:  vuln.Summary,
												Details:  vuln.Details,
												Severity: vuln.DatabaseSpecific.Severity,
											}
											ver.Vulnerabilities = append(ver.Vulnerabilities, vulnerability)
											ver.OverallSeverity = getOverallSeverity(ver.OverallSeverity, vulnerability.Severity)
											scanResponse.VulnerableVersions[introduced] = ver
										} else {
											vulnerabilities := []models.Vulnerability{
												{
													Summary:  vuln.Summary,
													Details:  vuln.Details,
													Severity: vuln.DatabaseSpecific.Severity,
												},
											}
											versionInfo := models.Version{
												Vulnerabilities: vulnerabilities,
												OverallSeverity: vuln.DatabaseSpecific.Severity,
											}
											scanResponse.VulnerableVersions[event.Introduced] = versionInfo
										}

									}
								}
							}
						}
					}
				}
				if req.Version != "" {
					for version := range scanResponse.VulnerableVersions {
						if version != req.Version {
							delete(scanResponse.VulnerableVersions, version)
						}
					}
				}
				vlsResponse.ScanResults = append(vlsResponse.ScanResults, scanResponse)
				myCache.Set(cacheKey, scanResponse, 2*time.Hour)
			}
		} else {

			errorResponse := models.ErrorResponse{
				Message: "Ecosystems Supported : PyPI, npm, crates.io, Go, Maven",
			}
			c.PureJSON(400, errorResponse)
		}

	}

	c.PureJSON(200, vlsResponse)
}

func getOverallSeverity(existingSeverity string, newSeverity string) string {
	severityOrder := map[string]int{
		"CRITICAL": 5,
		"HIGH":     4,
		"MODERATE": 3,
		"LOW":      2,
		"":         1,
	}

	newSeverity = strings.ToUpper(newSeverity)
	existingSeverity = strings.ToUpper(existingSeverity)
	if severityOrder[newSeverity] > severityOrder[existingSeverity] {
		return newSeverity
	}
	return existingSeverity
}
