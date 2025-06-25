import pandas as pd
import streamlit as st

#css
def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
load_css("style.css")
st.set_page_config(page_title="Table_Viewer", layout="wide")


if "tab" not in st.session_state:
    st.session_state.tab = "address"
if "file_path" not in st.session_state:
    st.session_state.file_path = None

#upload the file
if st.session_state.tab == "address":
    st.title("Path")
    st.markdown("Upload a CSV file")
    file_path = st.file_uploader("", type="csv")
    
    if file_path is not None:
        st.session_state.file_path = file_path
      

        if st.button("VIEW"):
            st.session_state.tab = "view"
            
            st.rerun()

#view the contents
elif st.session_state.tab == "view":
    st.title("View")

    if st.session_state.file_path is not None:
        try:
            df = pd.read_csv(st.session_state.file_path)
            st.dataframe(df, height=1000)
        except Exception as e:
            st.error(f"Error reading CSV file: {e}")

    if st.button("Back"):
        st.session_state.tab = "address"
        st.rerun()
