import pandas as pd
from datetime import datetime
import pycountry as pyc
import hashlib
import difflib

header_map = {
    "source_ip": ["src_ip", "source.ip", "ip_source"],
    "dest_ip": ["dst_ip", "destination_ip", "ip_dest"],
    "access_time": ["time", "timestamp", "log_time", "event_time"],
    "country_code": ["src_ip_country_code", "geo_country", "country", "location"],
    "dest_port": ["dst_port", "destination_port", "port"],
    "bytes_in": ["bytes_in", "bytes.received", "incoming_bytes"],
    "bytes_out": ["bytes_out", "bytes.sent", "outgoing_bytes"]
}

#GENERALIZE THE COLUMN NAMES

def map_columns(actual_headers, header_map):
    column_mapping = {}

    for standard, possible_names in header_map.items():

        matched = None
        for name in possible_names:
            if name in actual_headers:
                matched = name
                break

        if not matched:
            guess = difflib.get_close_matches(standard, actual_headers, n=1, cutoff=0.6)
            if guess:
                matched = guess[0]

        if matched:
            column_mapping[standard] = matched

    return column_mapping

#STEP2----GETTING FINGERPRINTS
def behaviour(info):

    time=datetime.strptime(info["access_time"],"%Y-%m-%dT%H:%M:%SZ").strftime("%I:%M:%p")
   # time=time_date.strftime("%H:%M")
    code=info["country_code"]
    port=info["dest_port"]
    bytesin=info["bytes_in"]
    bytesout=info["bytes_out"]
    country=pyc.countries.get(alpha_2=code.upper())
    if country:
        country=country.name
    else : 
        country="Invalid Code"
    
    bytes=""
    if(bytesout>bytesin): bytes="sent more data out than recieved"
    elif(bytesin>bytesout): bytes="recieved more data in than sent out"
    else: bytes="equal amount of data is sent and recieved"
    #From US, at 3AM, accessed port 22, sent more data out than received
    statement=f'From {country}, at {time}, accessed port {port}, {bytes}'
    return statement

#STEP3---HASHING
def code(pattern):
    return hashlib.sha256(pattern.encode('utf-8')).hexdigest()

data=pd.read_csv(".venv/sample_data.csv")
actual_headers = data.columns.tolist()
column_mapping = map_columns(actual_headers, header_map)
lst=[]


# with open(".venv/ip-list.txt") as f:
#     blacklisted_ips = set(line.strip() for line in f if line.strip())
    
   
    
for _, row in data.iloc[1:].iterrows():
    info = {
        "access_time": row[column_mapping["access_time"]],
        "bytes_in": row[column_mapping["bytes_in"]],
        "bytes_out": row[column_mapping["bytes_out"]],
        "source_ip": row[column_mapping["source_ip"]],
        "dest_ip": row[column_mapping["dest_ip"]],
        "dest_port": row[column_mapping["dest_port"]],
        "country_code": row[column_mapping["country_code"]],
    }
    fingerprt=behaviour(info)
    info["fingerprint"]=fingerprt
    info["dna"]=code(fingerprt)
    lst.append(info)


df=pd.DataFrame(lst)
df.to_csv('threat_output.csv')


#STEP4----GROUPING & DEFINING ALERT_LEVEL
high=20
medium=13
low=5
rare=3
dna_grp=df.groupby(['dna'])
fingerprint_eg=dna_grp['fingerprint'].first()
dna_eg=dna_grp['dna'].first()
print(type(dna_grp['dna'].value_counts()))
count=dna_grp['dna'].value_counts()
threat_level=""
if(count>=high): threat_level="High"
elif(count>=medium): threat_level="Medium"
elif(count>=low):threat_level="Low"
else : threat_level="Rare"
data={
    "behaviour":fingerprint_eg,
    "dna":dna_eg,
    "count":count,
    "threat_level":threat_level
}

pattern=pd.DataFrame(data).sort_values(by='count', ascending=False)
pattern.to_csv("patterns.csv",index=False,header=['Behaviour','DNA','Count'])


#STEP5---VALIDATION
def validate():
    prints=df.groupby(['fingerprint'])
    unique_count=prints['dna'].nunique()
    inconsistent = unique_count[unique_count> 1]
    consistent=inconsistent.size==0
    return consistent
    

#FINAL VALIDATION
if(validate()) :print(True) 
else : print(False)

    






    

    
    