from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import base64
import joblib
import pickle
import logging
import os
import dns.resolver
from email import message_from_bytes
from functools import lru_cache
from dotenv import load_dotenv

# Local modules
from modules import CertificateValidation as certval
from modules import DomainAndURL as DU
from modules import Email_Authentication as EA
from modules import Classify_Email as CE
from modules import Final_Classification as FC

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app instance
app = FastAPI()

# Environment variables
COMMON_WORDS_PATH = os.getenv("COMMON_WORDS_PATH", "common_words.pkl")
MODEL_PATH = os.getenv("MODEL_PATH", "model_with_metadata.joblib")

# Load model at startup with caching
@lru_cache(maxsize=1)
def load_model() -> tuple:
    """
    Load the model, threshold, common words, and word-to-index mapping.
    """
    try:
        logger.info("Loading model and metadata...")
        with open(COMMON_WORDS_PATH, 'rb') as f:
            common_words = pickle.load(f)

        model_with_metadata = joblib.load(MODEL_PATH)
        logger.info("Model and metadata loaded successfully.")
        return model_with_metadata["model"], model_with_metadata["threshold"], common_words, model_with_metadata["word_to_index"]
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        raise HTTPException(status_code=500, detail=f"Missing file: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        raise HTTPException(status_code=500, detail=f"Error loading model: {str(e)}")

# Dependency Injection
@app.get("/")
async def root():
    return {"message": "Phisherman Email API Running"}

# Define schema for email payload
class EmailPayload(BaseModel):
    raw: str

# Validate Base64
def is_valid_base64(s: str) -> bool:
    try:
        base64.urlsafe_b64decode(s)
        return True
    except Exception:
        return False

@app.post("/api/process-email")
async def process_email(payload: EmailPayload, model_data=Depends(load_model)):
    try:
        if not is_valid_base64(payload.raw):
            raise HTTPException(status_code=400, detail="Invalid Base64 encoding.")

        logger.info("Processing email...")
        raw_email = base64.urlsafe_b64decode(payload.raw)
        extracted_email = message_from_bytes(raw_email)

        # Certificate Validation
        cert_validation_result = certval.analyze_email_certificate(raw_email)
            
    # 🔹 Extract individual results
        
        certificate_status = cert_validation_result["Certificate Result"]
        certificate_reason = cert_validation_result["Certificate Reason"]
        reply_to_result = cert_validation_result["Reply-To Result"]
        reply_to_reason = cert_validation_result["Reply-To Reason"]

        # 🔹 Print the results
        print("\n📌 Email Certificate Analysis Report:")
        print(f"🔹 Certificate Result: {certificate_status}")
        print(f"🔹 Certificate Reason: {certificate_reason}")
        print(f"🔹 Reply-To Result: {reply_to_result}")
        print(f"🔹 Reply-To Reason: {reply_to_reason}")



        # Domain & URL Analysis
        results_domain = DU.analyze_email(raw_email)

        

        # 🔹 Extract individual results
       
        sender_domain_result = results_domain['Sender Domain']['Classification']
        sender_domain_reason = results_domain['Sender Domain']['Reason']
        url_analysis_result = results_domain['URLs']['Classification']
        url_analysis_reason = results_domain['URLs']['Reason']

        print("\n📌 Email Analysis Report\n")
        # Display Sender Domain Classification
        print("\n🔹 Sender Domain:")
        print(f"   Classification: {sender_domain_result}")
        print(f"   Reason: {sender_domain_reason}")

        # Display URL Classification
        print("\n🔹 URLs:")
        print(f"   Classification: {url_analysis_result}")
        print(f"   Reason: {url_analysis_reason}")



        # Classification
        model, threshold, common_words, word_to_index = model_data
        print("thresold.........",threshold)
        phishing_prediction = CE.classify_email(extracted_email, model, threshold, common_words, word_to_index)

        logger.info(f"Email classified as: {phishing_prediction}")
        logger.info("Email processed successfully.")

        spf_dkim_dmarc_result, spf_dkim_dmarc_reason = EA.classify_spf_dkim_dmarc(raw_email)
        print("\n📌 SPF/DKIM/DMARC Verification:")
        print(f"🔹 Classification: {spf_dkim_dmarc_result}")
        print(f"🔹 Reason:\n{spf_dkim_dmarc_reason}")

            # 🔥 Run Final Classification
        final_decision, reason = FC.classify_final(
            phishing_prediction,
            spf_dkim_dmarc_result,
            spf_dkim_dmarc_reason,
            certificate_status,
            certificate_reason,
            reply_to_result,
            reply_to_reason,
            sender_domain_result,
            sender_domain_reason,
            url_analysis_result,
            url_analysis_reason,
           
        )

        # 🔎 Display Results
        print("\n📌 FINAL EMAIL ANALYSIS REPORT:")
        print(f"🔹 Final Decision: {final_decision}")
        print(f"🔹 Reason:\n{reason}")


            

        return {
            "final_decision": final_decision,
            "final_reason": reason,
            
        }
    except HTTPException:
        raise  # Re-raise HTTPException to return the appropriate response
    except Exception as e:
        logger.error(f"Error processing email: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))