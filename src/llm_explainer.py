"""
LLM-Guided Explainable Intrusion Detection System
Module 3: LLM-Based Summarization and Explanation
"""

import json
from datetime import datetime
from typing import Dict, List, Optional

class LLMExplainer:
    """
    Generate natural language explanations for network anomalies
    Supports multiple LLM backends: OpenAI, Anthropic, or local models
    """
    
    def __init__(self, backend='anthropic', api_key=None, model='claude-3-sonnet'):
        """
        Initialize LLM explainer
        
        Args:
            backend: 'openai', 'anthropic', or 'local'
            api_key: API key for the service
            model: Model name to use
        """
        self.backend = backend
        self.api_key = api_key
        self.model = model
        
        if backend == 'openai' and api_key:
            import openai
            self.client = openai.OpenAI(api_key=api_key)
        elif backend == 'anthropic' and api_key:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            print("[WARNING] No API key provided. Using template-based explanations.")
            self.client = None
    
    def create_detection_prompt(self, detection_info: Dict, attack_context: Optional[Dict] = None) -> str:
        """
        Create a structured prompt for the LLM to explain the anomaly
        """
        prompt = f"""You are a cybersecurity expert analyzing network traffic anomalies. 

DETECTION DETAILS:
- Anomaly Detected: {detection_info['is_anomaly']}
- Confidence Level: {detection_info['confidence']:.2%}
- Severity: {detection_info['severity']}
- Model Used: {detection_info['model_used']}
- Detection Time: {detection_info['timestamp']}

TOP CONTRIBUTING FEATURES:
"""
        
        for feature, value in list(detection_info['top_features'].items())[:5]:
            prompt += f"- {feature}: {value:.4f}\n"
        
        if attack_context:
            prompt += f"\nATTACK CONTEXT:\n"
            prompt += f"- Attack Type: {attack_context.get('attack_type', 'Unknown')}\n"
            prompt += f"- Category: {attack_context.get('category', 'Unknown')}\n"
        
        prompt += """
Please provide a clear, concise explanation that includes:

1. SUMMARY: What type of network activity was detected? (2-3 sentences)
2. TECHNICAL DETAILS: What specific features or patterns indicate this anomaly?
3. RISK ASSESSMENT: What is the potential impact on the network?
4. RECOMMENDED ACTIONS: What should security teams do immediately?
5. PREVENTION: How can similar attacks be prevented in the future?

Keep the explanation accessible to both technical and non-technical stakeholders.
Use clear language and avoid unnecessary jargon.
"""
        
        return prompt
    
    def generate_explanation_with_llm(self, detection_info: Dict, attack_context: Optional[Dict] = None) -> Dict:
        """
        Generate explanation using actual LLM API
        """
        prompt = self.create_detection_prompt(detection_info, attack_context)
        
        try:
            if self.backend == 'openai' and self.client:
                response = self.client.chat.completions.create(
                    model=self.model or "gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    max_tokens=1000
                )
                explanation = response.choices[0].message.content
                
            elif self.backend == 'anthropic' and self.client:
                response = self.client.messages.create(
                    model=self.model or "claude-3-sonnet-20240229",
                    max_tokens=1000,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                explanation = response.content[0].text
            
            else:
                # Fallback to template
                explanation = self.generate_template_explanation(detection_info, attack_context)
            
            return {
                'explanation': explanation,
                'prompt': prompt,
                'generated_at': datetime.now().isoformat(),
                'backend': self.backend
            }
        
        except Exception as e:
            print(f"[ERROR] LLM generation failed: {e}")
            # Fallback to template
            explanation = self.generate_template_explanation(detection_info, attack_context)
            return {
                'explanation': explanation,
                'generated_at': datetime.now().isoformat(),
                'backend': 'template_fallback'
            }
    
    def generate_template_explanation(self, detection_info: Dict, attack_context: Optional[Dict] = None) -> str:
        """
        Generate explanation using templates (no LLM required)
        Useful for testing or when API is unavailable
        """
        is_anomaly = detection_info['is_anomaly']
        confidence = detection_info['confidence']
        severity = detection_info['severity']
        
        if not is_anomaly:
            return f"""
✓ NORMAL TRAFFIC DETECTED

The analyzed network activity appears to be legitimate with {confidence:.1%} confidence.
No security concerns identified at this time.

Recommended Actions:
- Continue routine monitoring
- No immediate action required
"""
        
        # Build explanation for anomaly
        explanation = f"""
⚠️ SECURITY ANOMALY DETECTED - {severity} SEVERITY

SUMMARY:
The intrusion detection system has identified suspicious network activity with {confidence:.1%} confidence. 
"""
        
        # Add attack-specific context
        if attack_context and 'attack_type' in attack_context:
            attack_type = attack_context['attack_type']
            explanation += f"This pattern is consistent with a {attack_type} attack. "
            
            # Attack-specific details
            attack_descriptions = {
                'DoS': 'A Denial of Service (DoS) attack attempts to overwhelm system resources, making services unavailable to legitimate users.',
                'Probe': 'A network probe or scan is attempting to gather information about the network infrastructure and identify potential vulnerabilities.',
                'R2L': 'A Remote-to-Local (R2L) attack is attempting to gain unauthorized access from a remote machine.',
                'U2R': 'A User-to-Root (U2R) attack is attempting to escalate privileges from normal user to root/administrator access.',
                'DDoS': 'A Distributed Denial of Service (DDoS) attack uses multiple compromised systems to flood the target.',
                'Botnet': 'Activity consistent with botnet communication has been detected, indicating possible malware infection.'
            }
            
            for key, desc in attack_descriptions.items():
                if key.lower() in attack_type.lower():
                    explanation += desc + "\n"
                    break
        
        explanation += f"""

TECHNICAL DETAILS:
Key indicators from network traffic analysis:
"""
        
        # Add top features
        top_features = list(detection_info['top_features'].items())[:3]
        for feature, value in top_features:
            explanation += f"- {feature.replace('_', ' ').title()}: Abnormal value detected ({value:.2f})\n"
        
        explanation += f"""

RISK ASSESSMENT:
"""
        
        if severity == "CRITICAL":
            explanation += """- IMMEDIATE ACTION REQUIRED
- High probability of active attack
- Potential for significant system compromise
- Data exfiltration or service disruption possible"""
        
        elif severity == "HIGH":
            explanation += """- Prompt investigation required
- Suspicious activity with clear malicious indicators
- Potential security breach in progress"""
        
        elif severity == "MEDIUM":
            explanation += """- Investigation recommended
- Anomalous behavior detected
- May indicate reconnaissance or early attack stages"""
        
        else:
            explanation += """- Low risk, but warrants attention
- Minor deviation from normal patterns
- Could be benign or early attack indicator"""
        
        explanation += f"""

RECOMMENDED ACTIONS:
1. Block the source IP address immediately if attack is confirmed
2. Review firewall and IDS rules to prevent similar traffic
3. Analyze affected systems for signs of compromise
4. Preserve logs for forensic analysis
5. Notify security team and stakeholders

PREVENTION:
- Implement rate limiting and traffic filtering
- Keep systems and software up to date
- Use network segmentation to limit attack surface
- Deploy additional monitoring on affected segments
- Review and update security policies

Generated by: {detection_info['model_used'].upper()} model at {detection_info['timestamp']}
"""
        
        return explanation
    
    def generate_batch_report(self, detections: List[Dict], title: str = "Network Security Report") -> str:
        """
        Generate a comprehensive report for multiple detections
        """
        report = f"""
{'=' * 80}
{title.upper()}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 80}

EXECUTIVE SUMMARY:
Total Detections Analyzed: {len(detections)}
"""
        
        # Count by severity
        severity_counts = {}
        anomaly_count = 0
        
        for detection in detections:
            if detection['is_anomaly']:
                anomaly_count += 1
                severity = detection['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        report += f"Anomalies Detected: {anomaly_count}\n"
        report += f"Normal Traffic: {len(detections) - anomaly_count}\n\n"
        
        if severity_counts:
            report += "Severity Breakdown:\n"
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity in severity_counts:
                    report += f"  {severity}: {severity_counts[severity]}\n"
        
        report += f"\n{'=' * 80}\nDETAILED FINDINGS:\n{'=' * 80}\n"
        
        # Detail each anomaly
        for i, detection in enumerate(detections, 1):
            if detection['is_anomaly']:
                report += f"\n[DETECTION #{i}]\n"
                report += f"Severity: {detection['severity']}\n"
                report += f"Confidence: {detection['confidence']:.2%}\n"
                report += f"Time: {detection['timestamp']}\n"
                report += "-" * 80 + "\n"
        
        report += f"\n{'=' * 80}\nEND OF REPORT\n{'=' * 80}\n"
        
        return report
    
    def format_for_dashboard(self, detection_info: Dict, explanation: str) -> Dict:
        """
        Format detection and explanation for dashboard display
        """
        return {
            'alert_id': f"IDS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': detection_info['timestamp'],
            'severity': detection_info['severity'],
            'confidence': f"{detection_info['confidence']:.2%}",
            'is_anomaly': detection_info['is_anomaly'],
            'model': detection_info['model_used'],
            'explanation': explanation,
            'top_features': detection_info['top_features'],
            'status': 'ACTIVE' if detection_info['is_anomaly'] else 'RESOLVED'
        }


# Example usage
if __name__ == "__main__":
    print("=" * 80)
    print("LLM-Based Explanation Module - Module 3")
    print("=" * 80)
    
    # Initialize explainer (template mode for demo)
    explainer = LLMExplainer(backend='template')
    
    print("\n[INFO] LLM Explainer initialized")
    print("\nSupported backends:")
    print("  1. OpenAI GPT-4")
    print("  2. Anthropic Claude")
    print("  3. Template-based (no API required)")
    
    # Example detection
    sample_detection = {
        'is_anomaly': True,
        'confidence': 0.92,
        'model_used': 'random_forest',
        'timestamp': datetime.now().isoformat(),
        'top_features': {
            'dst_bytes': 5000000,
            'count': 511,
            'srv_count': 511,
            'serror_rate': 0.0,
            'dst_host_count': 255
        },
        'severity': 'HIGH'
    }
    
    sample_context = {
        'attack_type': 'DoS',
        'category': 'Denial of Service'
    }
    
    print("\n[DEMO] Generating explanation for sample detection...")
    result = explainer.generate_explanation_with_llm(sample_detection, sample_context)
    
    print("\n" + "=" * 80)
    print("GENERATED EXPLANATION:")
    print("=" * 80)
    print(result['explanation'])
    
    print("\n" + "=" * 80)