import json

# Global data structure
output_data = {
    "findings": []
}

def add_finding(vulnerability_name, severity, description, remediation, location):
    """
    Adds a new finding if it does not exist, otherwise updates its locations.
    """
    for finding in output_data["findings"]:
        if finding["vulnerabilityName"] == vulnerability_name:
            # If the finding exists, update locations by appending the new location value directly
            if isinstance(finding["locations"], list):
                finding["locations"].append(location)
            else:
                finding["locations"] = [finding["locations"], location]
            return

    # If not found, create a new finding entry
    output_data["findings"].append({
        "vulnerabilityName": vulnerability_name,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "locations": [location]  # Store as a list
    })

def appDefinitionsToJson(url, application, environment, userTenantProvider, homeModuleKey, realDNS):
    description = {
        "URL": url,
        "Application": application,
        "Environment": environment,
        "User tenant provider": userTenantProvider,
        "Home module key": homeModuleKey,
        "Real DNS (enterprise only)": realDNS
    }

    add_finding(
        "App Definitions",
        "Info",
        description,
        "Restrict access to appDefinition.js and remove sensitive information.",
        "N/A"
    )

def mobileAppToJson(location):
    add_finding(
        "Mobile Application",
        "Info",
        "Mobile Application detected.",
        "",
        location
    )

def getTestScreensToJson(vulnerabilityName,location):
    add_finding(
        vulnerabilityName,
        "Info",
        "Potential test screens found.",
        "Review",
        location
    )

def getScreensToJson(vulnerabilityName,location):
    add_finding(
        vulnerabilityName,
        "Info",
        "All screens enumerated",
        "Review",
        location
    )    

def ckeditorToJson(description,location):
    add_finding(
        "CKEditor Cross-Site-Scripting Vulnerabilty",
        "High",
        "Mobile Application detected.",
        description,
        location
    )

def cve202224728ToJson(description,remediation,location):
    add_finding(
        "CVE-2022-24728",
        "High",
        description,
        remediation,
        location
    )

def cve202341592ToJson(description,remediation,location):
    add_finding(
        "CVE-2023-41592",
        "High",
        description,
        remediation,
        location
    )

def PDFTronToJson(description,remediation,location):
    add_finding(
        "PDFTron XSS",
        "High",
        description,
        remediation,
        location
    )

def ultimatePDFtoJson(description,location):
    add_finding(
        "Possible UltimatePDF Vulnerability",
        "Medium",
        description,
        "N/A",
        location
    )

def allResourcesToJson(location):
    add_finding(
        "Possible Exposed Resources",
        "Info",
        "Potential exploitable file found.",
        "Review",
        location
    )

def clientVariablesToJson(location):
    add_finding(
        "Client Variables",
        "Medium",
        "Potential default values found in one or more ClientVar",
        "Review",
        location
    )    

def getOS11RolesToJson(vulnerabilityName,location):
    add_finding(
        vulnerabilityName,
        "Info",
        "OS11 Roles Enumeration",
        "Review",
        location
    )

def getODCRolesToJson(vulnerabilityName,location):
    add_finding(
        vulnerabilityName,
        "Info",
        "ODC Roles Enumeration",
        "Review",
        location
    )    

def reactiveLoginScreenToJson(vulnerabilityName,description,location):
    add_finding(
        vulnerabilityName,
        "High",
        description,
        "Review",
        location
    )    

def phoneLoginScreenToJson(vulnerabilityName,description,location):
    add_finding(
        vulnerabilityName,
        "High",
        description,
        "Review",
        location
    )

def sapInformationToJson(description,location):
    add_finding(
        "Exposed SAP Information",
        "Medium",
        description,
        "Review",
        location
    )        

def ectModuleToJson(description,remediation,location):
    add_finding(
        "ECT Provider Remote Code Execution Vulnerability",
        "Critical",
        description,
        remediation,
        location
    )
        

def printFindings():
    print(json.dumps(output_data, indent=4))