


---

# 🎯 **Use Case**  
**Data Exfiltration from PIP'd Employee**  

## 📚 **Scenario:**  
An employee named John Doe, working in a sensitive department, was recently placed on a performance improvement plan (PIP). After displaying concerning behavior, management suspects John may be planning to steal proprietary information and leave the company. The investigation involves analyzing activities on John’s corporate device (`windows-target-1`) using Microsoft Defender for Endpoint (MDE).  

---

## 📊 **Incident Summary and Findings**  

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:** Frequent creation of `.zip` files in a folder labeled "backup."  
   - **Detection Query (KQL):**  

     ```kql
     DeviceFileEvents
     | where DeviceName == "windows-target-1"
     | where FileName endswith ".zip"
     | order by Timestamp desc
     ```
![Screenshot 2025-01-05 172716](https://github.com/user-attachments/assets/4fdf9cf4-4fed-4935-bfea-bb76d5b01144)

     
2. **⚙️ Process Analysis:**  
   - **Observed Behavior:** Around the same time as the archive creation, a PowerShell script silently installed 7-Zip, used it to compress employee data into `.zip` files.  
   - **Detection Query (KQL):**  

     ```kql
     let VMName = "windows-target-1";
     let specificTime = datetime(2025-01-05T21:48:40.6546522Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
     ```
![Screenshot 2025-01-05 180046](https://github.com/user-attachments/assets/12d51ef5-8b84-4b41-9123-99adcbd3edbe)


   3. **🌐 Network Exfiltration Check:**  
   - **Observed Behavior:** No evidence of data exfiltration via network logs during the time frame.  

   - **Detection Query (KQL):**  

     ```kql
     let VMName = "windows-target-1";
     let specificTime = datetime(2025-01-05T21:48:40.6546522Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     ```  

4. **📝 Response:**  
   - Shared findings with the manager, highlighting automated archive creation and no immediate signs of exfiltration. Awaiting further instructions.

---

## 🛡️ **MITRE ATT&CK Framework TTPs**  

| **Tactic**           | **Technique**                                                                                     | **ID**            | **Description**                                                                                                                                                 |  
|-----------------------|---------------------------------------------------------------------------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| 🛠️ **Execution**      | PowerShell                                                                                       | T1059.001         | PowerShell scripts were used to silently install 7-Zip and execute file compression commands.                                                                   |  
| 📦 **Collection**      | Archive Collected Data                                                                           | T1560.001         | Employee data was compressed into `.zip` files using 7-Zip, possibly for easier handling or exfiltration.                                                       |  
| 📂 **Exfiltration**    | Exfiltration Over Alternative Protocol                                                           | T1048             | Although no network exfiltration was detected, the technique aligns with the potential misuse of alternate protocols for stealthy data transfer.                |  
| 🔍 **Discovery**       | Process Discovery                                                                                | T1057             | Processes were reviewed to identify activities surrounding the installation and use of 7-Zip for archiving.                                                     |  

---

### 🧑‍💻 **Next Steps**  
1. Monitor John’s account activity for unusual access or privilege escalation.  
2. Implement DLP (Data Loss Prevention) measures to alert on potential data exfiltration.  
3. Escalate findings to management and recommend a follow-up review of John's device for additional forensic artifacts.  

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Created By:
- **Author Name**: Trevino Parker
- **Author Contact**: https://www.linkedin.com/in/trevinoparker/
- **Date**: Jan 5, 2025

## Validated By:
- **Reviewer Name**: Josh Madakor
- **Reviewer Contact**: https://www.linkedin.com/in/joshmadakor/
- **Validation Date**: Jan , 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `Jan 5, 2025`  | `Trevino Parker`   
