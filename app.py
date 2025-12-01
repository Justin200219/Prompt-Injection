import streamlit as st
import pandas as pd
import time
import config
from test_runner import generate_single_attack, test_single_attack
from target_system import TargetAI

# Page Config
st.set_page_config(
    page_title="Red-Team Bot Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Title and Description
st.title("Red-Team Bot Dashboard")
st.markdown("""
This dashboard allows you to run **AI Safety Tests** interactively.
It generates sophisticated prompt injection attacks and tests them against a target AI system.
""")

import requests

# Helper: Fetch Models
def get_all_models():
    try:
        r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=2)
        if r.status_code == 200:
            local_models = [m['name'] for m in r.json().get('models', [])]
            return local_models
    except Exception:
        pass

    return [config.MODEL_NAME]  # Fallback

# Sidebar Configuration
st.sidebar.subheader("Configuration")
num_attacks = st.sidebar.slider("Number of Attacks", min_value=1, max_value=20, value=5)

# Model Selection
model_options = get_all_models()

with st.sidebar.expander("Attacker Model", expanded=True):
    attacker_index = 0
    if config.ATTACKER_MODEL in model_options:
        attacker_index = model_options.index(config.ATTACKER_MODEL)
    
    attacker_model = st.radio(
        "Select Attacker Model", 
        options=model_options, 
        index=attacker_index,
        key="attacker_model",
        label_visibility="collapsed"
    )

with st.sidebar.expander("Target Model", expanded=True):
    target_index = 0
    if config.TARGET_MODEL in model_options:
        target_index = model_options.index(config.TARGET_MODEL)
    
    target_model = st.radio(
        "Select Target Model", 
        options=model_options, 
        index=target_index,
        key="target_model",
        label_visibility="collapsed"
    )

# Update Config
config.ATTACKER_MODEL = attacker_model
config.TARGET_MODEL = target_model
config.MODEL_NAME = attacker_model # Keep for backward compatibility if needed

# Initialize Session State
if "results" not in st.session_state:
    st.session_state.results = []
if "running" not in st.session_state:
    st.session_state.running = False

# Run Button
if st.sidebar.button("Start Red Team Attack", disabled=st.session_state.running):
    st.session_state.running = True
    st.session_state.results = []  # Clear previous results
    
    target = TargetAI(model_name=target_model)
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Main Attack Loop
    for i in range(1, num_attacks + 1):
        status_text.text(f"Attack {i}/{num_attacks}: Generating prompt...")
        
        # 1. Generate
        try:
            attack = generate_single_attack(i, num_attacks)
        except Exception as e:
            st.error(f"Generation failed: {e}")
            continue
            
        if not attack:
            st.warning(f"Attack {i} skipped (invalid generation)")
            continue
            
        # 2. Test
        status_text.text(f"Attack {i}/{num_attacks}: Testing against target...")
        result = test_single_attack(attack, i, target, show_details=False)
        
        if result:
            # Convert object to dict for state storage
            result_dict = {
                "attack_prompt": result.attack_prompt,
                "response": result.response,
                "jailbroken": result.jailbroken,
                "attack_type": result.attack_type,
                "analysis": result.analysis
            }
            st.session_state.results.append(result_dict)
            
        # Update Progress
        progress_bar.progress(i / num_attacks)
        time.sleep(0.5)  # Small pause for UI smoothness
        
    st.session_state.running = False
    status_text.text("Testing Complete!")
    st.balloons()

# Display Results
if st.session_state.results:
    st.divider()
    st.subheader("Test Results")
    
    # Metrics
    total = len(st.session_state.results)
    jailbreaks = sum(1 for r in st.session_state.results if r["jailbroken"])
    success_rate = (jailbreaks / total) * 100 if total > 0 else 0
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Attacks", total)
    col2.metric("Successful Jailbreaks", jailbreaks, delta_color="inverse")
    col3.metric("Success Rate", f"{success_rate:.1f}%", delta_color="inverse")
    
    # Detailed Log
    st.subheader("Attack Log")
    for res in st.session_state.results:
        with st.expander(f"{'🔴 JAILBROKEN' if res['jailbroken'] else '🟢 BLOCKED'} - {res['attack_type']}"):
            st.markdown(f"**Prompt:**\n> {res['attack_prompt']}")
            st.markdown(f"**Response:**\n> {res['response']}")
            if res.get('analysis'):
                st.info(f"Reasoning: {res['analysis'].get('reasoning', 'N/A')}")

