import google.generativeai as genai

# Put your API key here
GEMINI_API_KEY = "YOUR_API_KEY"

genai.configure(api_key=GEMINI_API_KEY)

# Get the model (FREE)
gemini_model = genai.GenerativeModel("gemini-1.5-flash")

def gemini_analyze(prompt):
    """Universal function to call Gemini for any analysis."""
    try:
        response = gemini_model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"[Gemini Error] {e}"
