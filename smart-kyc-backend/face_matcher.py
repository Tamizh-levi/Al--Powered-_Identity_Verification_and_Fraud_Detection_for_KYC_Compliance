import os
import glob
import torch
import numpy as np
from PIL import Image
# NOTE: cv2 is only imported but not strictly used in this core logic
import cv2 
from facenet_pytorch import MTCNN, InceptionResnetV1

class FaceMatcher:

    def __init__(self):
        # Determine device (CPU or GPU)
        self.device = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')
        
        # Face Detector: MTCNN for high-accuracy face and landmark detection
        self.detector = MTCNN(
            margin=20, 
            keep_all=False, 
            post_process=False,
            device=self.device
        )

        # Face Embedding Model: InceptionResnetV1 trained on VGG Face 2 dataset.
        # This architecture is commonly known as FaceNet and produces 512-dimensional embeddings.
        self.model = InceptionResnetV1(pretrained='vggface2').eval().to(self.device)

        self.live_folder = "static/live_photos"
        os.makedirs(self.live_folder, exist_ok=True)

    def save_live_photo(self, file, user_id):
        """Saves the live photo and removes older versions."""
        old = glob.glob(os.path.join(self.live_folder, f"user_{user_id}_live.*"))
        for f in old:
            try:
                os.remove(f)
            except:
                pass

        # Handle file extension robustly
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else 'jpg'
        fname = f"user_{user_id}_live.{ext}"
        save_path = os.path.join(self.live_folder, fname)

        file.seek(0)
        file.save(save_path)
        return save_path

    def get_embedding(self, image_path):
        """Extracts face embedding from an image file."""
        img = Image.open(image_path).convert('RGB')

        # 1. Detect face and crop/process (tensor output)
        face_tensor = self.detector(img)

        # FIX: Ensure face_tensor is not None before proceeding
        if face_tensor is None:
            # If MTCNN couldn't find a face, return None
            return None

        # 2. Compute embedding
        with torch.no_grad():
            # Add batch dimension (unsqueeze(0)) and ensure tensor is on the correct device
            emb = self.model(face_tensor.unsqueeze(0).to(self.device))
        
        # Return the embedding tensor (removing batch dimension)
        return emb[0]

    def match_faces(self, id_path, live_path):
        """Compares two faces using cosine similarity on embeddings."""

        if not os.path.exists(id_path):
            return {"status": "LOW", "match_percent": "0%", "error": "ID image not found"}

        if not os.path.exists(live_path):
            return {"status": "LOW", "match_percent": "0%", "error": "Live image not found"}

        emb1 = self.get_embedding(id_path)
        emb2 = self.get_embedding(live_path)

        # CHECK 1: Ensure detection succeeded for ID
        if emb1 is None:
            return {"status": "LOW", "match_percent": "0%", "error": "No valid face detected in ID image (Aadhaar)."}

        # CHECK 2: Ensure detection succeeded for Live Photo
        if emb2 is None:
            return {"status": "LOW", "match_percent": "0%", "error": "No valid face detected in LIVE image."}

        # Cosine similarity (ranges from -1 (opposite) to 1 (identical))
        distance = torch.nn.functional.cosine_similarity(emb1.cpu(), emb2.cpu(), dim=0).item()

        # Convert to a 0-100% scale: (distance + 1) / 2 * 100
        similarity = ((distance + 1) / 2) * 100 

        # Set result level
        if similarity >= 85:
            status = "HIGH"
        elif similarity >= 70:
            status = "MEDIUM"
        else:
            status = "LOW"

        return {
            "status": status,
            "match_percent": f"{similarity:.2f}%",
            "raw_distance": float(distance) 
        }