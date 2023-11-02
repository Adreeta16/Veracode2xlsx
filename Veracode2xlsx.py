import xml.etree.ElementTree as ET
import csv
import sys
import pandas as pd
import argparse
import os

def parsingxmldata(inxml):
    mytree = ET.parse(inxml)
    myroot = mytree.getroot()
    csv_file = "veracode_report.csv"

    with open(csv_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Severity", "Vulnerability Name", "Issue ID", "Description", "Remediation", "Sourcepath_Line", "Mitigation Status"])

        for severity in myroot.findall("{https://www.veracode.com/schema/reports/export/1.0}severity/{https://www.veracode.com/schema/reports/export/1.0}category/{https://www.veracode.com/schema/reports/export/1.0}cwe/{https://www.veracode.com/schema/reports/export/1.0}staticflaws/"):
            check_sev = severity.get("severity")
            if check_sev == "5":
                check_sev = "Critical"
            elif check_sev == "4":
                check_sev = "High"
            elif check_sev == "3":
                check_sev = "Medium"
            elif check_sev in ("2", "1"):
                check_sev = "Low"
            elif check_sev == "0":
                check_sev = "Informational"
            
            Category = severity.get("categoryname").replace(",", "")
            Issue_Id = severity.get("issueid")
            desc = severity.get("description").split('\r\n\r\n', 1)
            Description = desc[0].replace(",", "")
            Remediation = desc[1].replace('\r', '').replace('\n', '').replace(",", "")
            file_path = severity.get("sourcefile") + ":" + severity.get("line")
            Mitigation_Status = severity.get("mitigation_status")
            
            writer.writerow([check_sev, Category, Issue_Id, Description, Remediation, file_path, Mitigation_Status])

    #print(f"Data has been written to '{csv_file}'.")

def convert_csv_to_excel(input_csv, output_xlsx):
    try:
        df = pd.read_csv(input_csv)
        df.to_excel(output_xlsx, index=False)
        print(f"Veracode excel file generated : '{output_xlsx}'")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Convert Veracode XML report to CSV')
    parser.add_argument('xml_path', help='Path to the Veracode XML report')
    args = parser.parse_args()

    parsingxmldata(args.xml_path)
    
    # Convert CSV to Excel
    convert_csv_to_excel("veracode_report.csv", "veracode_report.xlsx")
    os.remove('veracode_report.csv')

if __name__ == '__main__':
    main()
