import requests
from bs4 import BeautifulSoup

class XSSDetector:
    def __init__(self, target_url):
        self.target_url = target_url

    def detect_xss(self):
        # Send a GET request to the target URL
        response = requests.get(self.target_url)
        if response.status_code == 200:
            # Extract input fields from the HTML form
            input_fields = self.extract_input_fields(response.text)
            if input_fields:
                print(input_fields)
            else:
                print("No inputs")


            if input_fields:
                # Test each input field for XSS vulnerability
                for field in input_fields:
                    payload = "<script>alert('XSS Vulnerability Found!')</script>"
                    modified_url = self.inject_payload(self.target_url, field, payload)
                    modified_response = requests.get(modified_url)
                    # print(modified_response.text)
                    print(modified_url)
                    if payload in modified_response.text:
                        print(f"XSS Vulnerability detected in input field: {field}")
                    else:
                        print(f"No XSS Vulnerability detected in input field: {field}")


            else:
                print("No input fields found on the page.")


        else:
            print("Failed to fetch the page. Status code:", response.status_code)


    def extract_input_fields(self, html_content):
        input_fields = []
        soup = BeautifulSoup(html_content, 'html.parser')
        # Find all input elements in the HTML content
        input_tags = soup.find_all('input')
        # Extract information about each input element
        for tag in input_tags:
            input_info = {}
            input_info['type'] = tag.get('type', '')
            input_info['name'] = tag.get('name', '')
            input_info['id'] = tag.get('id', '')
            input_info['value'] = tag.get('value', '')
            input_info['class'] = tag.get('class', [])
            input_fields.append(input_info)
        return input_fields


  

    def inject_payload(self, url, field, payload):
        # Modify the URL to include the XSS payload in the specified input field
        # For simplicity, let's assume the input field is part of the query string
        # Modify this according to the structure of the website's input fields
        modified_url = url + f"?{field['name']}={payload}"
        return modified_url

# Example usage:
if __name__ == "__main__":
    target_url = "https://www.codelatte.id/labs/xss/1.php"

    detector = XSSDetector(target_url)
    detector.detect_xss()
