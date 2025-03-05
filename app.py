import re
import secrets
import string
import hashlib
import requests
import streamlit as st
import math

st.set_page_config(page_title="Password Strength Checker", page_icon="🔐", layout="centered")
st.title("Password Strength Checker")
st.write("How safe is your password? Test its strength or generate a rock-solid one in seconds!")

def check_password_strength(password):
    score = 0
    feedback = []

    # Check Length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")
     
    if len(password) >= 12: # Bonus point for longer passwords
        score += 1

    # Check Uppercase & Lowercase
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else: 
        feedback.append("Include both uppercase and lowercase letters.")
    
    # Check Digit
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add at least one number (0-9).")

    # Check Special Characters
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        feedback.append("Include at least one special character (!@#$%^&*).")

    return score, feedback

# Function to check if password has been compromised (HIBP API)
def check_breached_password(password):
    """Check if a password is found in data breaches using Have I Been Pwned API."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        response.raise_for_status() # Raise error if request fails

        # Check if suffix is in response
        if suffix in response.text:
            return True # Password found in breaches
        return False
    except requests.exceptions.RequestException:
        st.warning("⚠️ Unable to check breached passwords.")
        return None # Return None if API fails
    
# Function to generate a strong password
def generate_strong_password(length=12):
    """Generate a secure password."""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(characters) for _ in range(length))

# Function to estimate password cracking time
def estimate_cracking_time(password):
    """Estimates the time required to crack the password."""
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*" for c in password):
        charset_size += 8
    
    entropy = len(password) * math.log2(charset_size)
    seconds_to_crack = 2 ** entropy / (10 ** 12)

    if score < 3:
        if seconds_to_crack < 60:
            return "Time to crack: **A few seconds**"
        elif seconds_to_crack < 3600:
            return f"Time to crack: **{int(seconds_to_crack // 60)} minutes**"
        elif seconds_to_crack < 86400:
            return f"Time to crack: **{int(seconds_to_crack // 3600)} hours**"
        else:
            return f"Time to crack: **{int(seconds_to_crack // 86400)} days**"
        
    if seconds_to_crack < 31536000:
        return f"Time to crack: **At least 1 year**"
    elif seconds_to_crack < 3153600000:
        return f"Time to crack: **{int(seconds_to_crack // 31536000)} years**"
    elif seconds_to_crack < 3153600000000:
        millions = seconds_to_crack // 31536000000
        return f"Time to crack: **{max(1,int(millions))} million years**"
    elif seconds_to_crack < 3153600000000000:
        billions = seconds_to_crack // 31536000000000
        return f"Time to crack: **{max(1, int(billions))} billion years**"
    else:
        return "Time to crack: **Trillions of years (Hackers might retire first!)**"

# Function to give review
def password_review(score):
    """Returns a review based on password strength."""
    if score >= 5:
        return "Excellent choice! Even cybersecurity professionals would have a hard time cracking this one."
    elif score >=3:
        return "A decent effort! Strengthen it a bit more, and it will be as reliable as a well-made cup of chai."
    else:
        return "This password lacks security—much like a shop without a shutter. Consider making it stronger!"
    
# UI
password = st.text_input("Enter your password:", type="password")
if password: 
    score, feedback = check_password_strength(password)

    # Check if password is breached
    breached = check_breached_password(password)
    if breached:
        st.error("This password has been found in data breaches! Choose a different one.")
        score = 1
    elif breached is None:
        st.warning("Breach check unavailable. Strength check results only.")

    # Show strength level
    if score >= 5:
        st.success("✅ Strong Password!")
    elif score >= 3:
        st.warning("⚠️ Moderate Password - Consider adding more security features.")
    else:
        st.error("❌ Weak Password - Improve it with the suggestions below.")

    # Display time to crack
    time_to_crack = estimate_cracking_time(password)
    st.write(f"⏳ {time_to_crack}")

    # Review
    review = password_review(score)
    st.write(f"💡 **Review:** {review}")
    # Show Feedback
    if feedback:
        st.write("### Suggestions:")
        for tip in feedback:
            st.write(f"- {tip}")

# Generate Password Button
if st.button("Generate Strong Password", key="generate", help="Click to generate a secure password"):
    strong_password = generate_strong_password()
    st.write("### Suggested Strong Password:")
    st.code(strong_password, language="bash")

# Privacy Information
st.write("🔒 **Privacy First:** Your password is never stored and remains entirely secure, ensuring complete confidentiality.")