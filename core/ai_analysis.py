import os
import logging
import json
from typing import Dict, Optional, List
import mistralai
import requests
from huggingface_hub import HfApi

class AISecurityAnalyzer:
    def __init__(self):
        self.mistral_api_key = os.environ.get("MISTRAL_API_KEY")
        self.hf_api_key = os.environ.get("HUGGINGFACE_API_KEY")
        self.codepal_api_key = os.environ.get("CODEPAL_API_KEY")
        
        # Initialize clients only if API keys are available
        self.mistral_client = mistralai.MistralClient(api_key=self.mistral_api_key) if self.mistral_api_key else None
        self.hf_api = HfApi(token=self.hf_api_key) if self.hf_api_key else None
        
    async def analyze_scan_results(self, scan_results: List[Dict]) -> Dict:
        """Analyze scan results using multiple AI models."""
        try:
            security_summary = await self._get_mistral_analysis(scan_results)
        except Exception as e:
            logging.error(f"Mistral analysis failed: {str(e)}")
            security_summary = "AI analysis currently unavailable"

        try:
            vulnerability_assessment = await self._get_codepal_assessment(scan_results)
        except Exception as e:
            logging.error(f"CodePal assessment failed: {str(e)}")
            vulnerability_assessment = []

        try:
            risk_classification = await self._get_huggingface_classification(scan_results)
        except Exception as e:
            logging.error(f"HuggingFace classification failed: {str(e)}")
            risk_classification = "Unknown"

        return {
            "summary": security_summary,
            "vulnerabilities": vulnerability_assessment,
            "risk_level": risk_classification
        }
    
    async def _get_mistral_analysis(self, scan_results: List[Dict]) -> str:
        """Get security analysis from Mistral AI."""
        if not self.mistral_client:
            return "Mistral AI analysis not available (API key not configured)"
            
        try:
            # Format scan results for better readability
            formatted_results = json.dumps(scan_results, indent=2)
            
            # Create a clear prompt for the AI
            system_prompt = """You are a cybersecurity expert analyzing port scan results. 
            Provide a concise security assessment focusing on:
            1. Open ports and their potential security implications
            2. Known vulnerable services
            3. Recommendations for security improvements
            Keep the response brief and actionable."""
            
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze these port scan results and provide a security assessment:\n{formatted_results}"}
            ]
            
            # Make API call with error handling
            try:
                response = self.mistral_client.chat(
                    model="mistral-tiny",  # Using tiny model for faster response
                    messages=messages
                )
                return response.choices[0].message.content
            except mistralai.MistralAPIError as e:
                logging.error(f"Mistral API error: {str(e)}")
                return "Unable to generate security analysis at this time"
            
        except Exception as e:
            logging.error(f"Error in Mistral analysis: {str(e)}")
            return "Error generating security analysis"
    
    async def _get_codepal_assessment(self, scan_results: List[Dict]) -> List[Dict]:
        """Get vulnerability assessment from CodePal.ai."""
        if not self.codepal_api_key:
            logging.warning("CodePal API key not configured")
            return []
            
        try:
            headers = {
                "Authorization": f"Bearer {self.codepal_api_key}",
                "Content-Type": "application/json"
            }
            
            # Format the payload with relevant scan information
            payload = {
                "scan_data": {
                    "ports": [result for result in scan_results if result["state"] == "open"],
                    "services": [{"port": r["port"], "service": r["service"]} 
                               for r in scan_results if r["state"] == "open"]
                },
                "analysis_type": "security_assessment",
                "include_cve_data": True
            }
            
            try:
                response = requests.post(
                    "https://api.codepal.ai/v1/security/analyze",
                    headers=headers,
                    json=payload,
                    timeout=10  # Add timeout
                )
                
                if response.status_code == 200:
                    vulnerabilities = response.json().get("vulnerabilities", [])
                    return [{"description": v["description"], "severity": v["severity"]} 
                           for v in vulnerabilities]
                else:
                    logging.error(f"CodePal API error: {response.status_code}")
                    return []
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"CodePal API request failed: {str(e)}")
                return []
                
        except Exception as e:
            logging.error(f"Error in CodePal assessment: {str(e)}")
            return []
    
    async def _get_huggingface_classification(self, scan_results: List[Dict]) -> str:
        """Classify security risk level using HuggingFace model."""
        if not self.hf_api:
            return "Unknown (API key not configured)"
            
        try:
            # Use a specialized security classification model
            api_url = "https://api-inference.huggingface.co/models/microsoft/security-aware-bert"
            headers = {"Authorization": f"Bearer {self.hf_api_key}"}
            
            # Prepare input focusing on security-relevant information
            open_ports = [r for r in scan_results if r["state"] == "open"]
            input_text = f"Security scan detected {len(open_ports)} open ports. "
            input_text += "Services running: " + ", ".join(
                f"{r['service']} on port {r['port']}" for r in open_ports
            )
            
            payload = {
                "inputs": input_text,
                "options": {"wait_for_model": True}
            }
            
            try:
                response = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    # Map confidence scores to risk levels
                    if isinstance(result, list) and result:
                        scores = result[0]
                        if scores.get("score", 0) > 0.7:
                            return "High"
                        elif scores.get("score", 0) > 0.3:
                            return "Medium"
                        else:
                            return "Low"
                return "Medium"  # Default to Medium if unable to determine
                
            except requests.exceptions.RequestException as e:
                logging.error(f"HuggingFace API request failed: {str(e)}")
                return "Unknown"
                
        except Exception as e:
            logging.error(f"Error in HuggingFace classification: {str(e)}")
            return "Unknown"
