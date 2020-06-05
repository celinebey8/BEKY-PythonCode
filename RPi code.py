import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto import Random
from Crypto.Cipher import AES


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import serial
import pynmea2
import paho.mqtt.client as mqtt
import json
from random import *
from datetime import datetime
import binascii
from sklearn.neighbors import KNeighborsClassifier
import pandas as pd

# AES Encryption 
class Cryptor(object):

    # AES-256 key (32 bytes)
    KEY = "01ab38d5e05c92aa098921d9d4626107133c7e2ab0e4849558921ebcc242bcb0"
    BLOCK_SIZE = 16

    @classmethod
    def _pad_string(cls, in_string):
        '''Pad an input string according to PKCS#7'''
        in_len = len(in_string)
        pad_size = cls.BLOCK_SIZE - (in_len % cls.BLOCK_SIZE)
        return in_string.ljust(in_len + pad_size, chr(pad_size))

    @classmethod
    def _unpad_string(cls, in_string):
        '''Remove the PKCS#7 padding from a text string'''
        in_len = len(in_string)
        pad_size = in_string[-1]
        if pad_size > cls.BLOCK_SIZE:
            raise ValueError('Input is not padded or padding is corrupt')
        return in_string[:in_len - pad_size]

    @classmethod
    def generate_iv(cls, size=16):
        return Random.get_random_bytes(size)

    @classmethod
    def encrypt(cls, in_string, in_key, in_iv=None):
        '''
        Return encrypted string.
        @in_string: Simple str to be encrypted
        @key: hexified key
        @iv: hexified iv
        '''
        key = binascii.a2b_hex(in_key)
        
        if in_iv is None:
            iv = cls.generate_iv()
            in_iv = binascii.b2a_hex(iv)
        else:
            iv = binascii.a2b_hex(in_iv)
        
        aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        return in_iv, aes.encrypt(cls._pad_string(in_string))

    @classmethod
    def decrypt(cls, in_encrypted, in_key, in_iv):
        '''
        Return encrypted string.
        @in_encrypted: Base64 encoded 
        @key: hexified key
        @iv: hexified iv
        '''
        key = binascii.a2b_hex(in_key)
        iv = binascii.a2b_hex(in_iv)
        aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)		
        decrypted = aes.decrypt(binascii.a2b_base64(in_encrypted).rstrip())
        
        return cls._unpad_string(decrypted)

#------------------------------------------

sensor_value = -1

mqtt_broker_address = "212.98.137.194"
mqtt_port = 1883
ser = serial.Serial('/dev/ttyACM1', 9600)
serialGPS = serial.Serial("/dev/ttyAMA0", 9600, timeout=0.5)
password = "bekyPass".encode()
padder = padding.PKCS7(128).padder()

def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    if(rc == 0):
        print("connection Successful")
    else:
        print("connection refused")
    client.subscribe("application/19/device/804a2bad98eef9b1/rx") 
    print("subscribed")

def on_message(client, userdata, msg):
    print(msg.payload)
    
def parseGPS(str):
    if (str.find('GGA') > 0):
        msg = pynmea2.parse(str)
        location = ("Lat: %s %s -- Lon: %s %s -- Altitude: %s %s" % (msg.lat,msg.lat_dir,msg.lon,msg.lon_dir,msg.altitude,msg.altitude_units))
        return location

def checkvalue (fieldname, value):
    if fieldname == "blood_pressure":
        if value == "0\r\n":
            return randint(100, 119)
        elif value == "1\r\n":
            return randint(120, 139)
        elif value == "2\r\n":
            return randint(140, 179)
        elif value == "3\r\n":
            return randint(180, 200)
            # Handle with priority
        else:
            return ("Invalid")
    elif fieldname == "heart_rate":
        if value == "0\r\n":
            return randint(60, 100)
        elif value == "1\r\n":
            return randint(101, 120)
        elif value == "2\r\n":
            return randint(121, 180)
        else:
            return ("Invalid")
    elif fieldname == "glucose":
        if value == "0\r\n":
            return randint(70, 119)
        elif value == "1\r\n":
            return randint(120, 140)
        else:
            return ("Invalid")
    elif fieldname == "temperature":
        return float(value)
    elif fieldname == "fall":
        return  int(value)
    
def initialize(patient_data):
        patient_data['temperature'] = -1
        patient_data['glucose'] = -1
        patient_data['blood_pressure'] = -1
        patient_data['heart_rate'] = -1
        patient_data['fall'] = -1
        
def handle_data(patient_data):
    prediction(patient_data)
    if (patient_data['critical'] == 1):
        patient_data['data_id'] = patient_data['data_id'] + 1
        patient_data = (json.dumps(patient_data))
        iv, encrypted = Cryptor.encrypt(patient_data, Cryptor.KEY)
        result = {
            "key": Cryptor.KEY,
            "iv": iv.decode('utf-8'),
            "ciphertext": (binascii.b2a_base64(encrypted).rstrip()).decode('utf-8')
        }
        res = json.dumps(dict(result))
        print('\nSending data\n')
        client.publish("application/19/device/804a2bad98eef9b1/rx", payload=res, qos=0, retain=False)
        print('Data sent\n')
        initialize(patient_data)
    else:
        if ((hour == 0 or hour == 6 or hour == 12 or hour == 18) & (minute == 0)):
            patient_data['data_id'] = patient_data['data_id'] + 1
            patient_data = (json.dumps(patient_data))
            iv, encrypted = Cryptor.encrypt(patient_data, Cryptor.KEY)
            result = {
                "key": Cryptor.KEY,
                "iv": iv.decode('utf-8'),
                "ciphertext": (binascii.b2a_base64(encrypted).rstrip()).decode('utf-8')
            }
            res = json.dumps(dict(result))
            print('\nSending data\n')
            client.publish("application/19/device/804a2bad98eef9b1/rx", payload=res, qos=0, retain=False)
            print('Data sent\n')
            

def patient_access(patient_data, fieldname, value):
    sensor_value = checkvalue(fieldname, value)
    if(patient_data[fieldname] != sensor_value):
        patient_data[fieldname] = sensor_value
        print('After access\n')
        print(patient_data)
        return patient_data

client = mqtt.Client()
client.username_pw_set("user", "bonjour")
client.on_connect = on_connect
client.on_message = on_message

client.connect(mqtt_broker_address, mqtt_port, 60)

# sex: 0 -> female // 1 -> male

patient_data0 = {'patient_id': 0, 'sex': 0, 'birthdate': '1965-07-22', 'age': datetime.now().year - 1965, 'dr_id': 0, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data1 = {'patient_id': 1, 'sex': 0, 'birthdate': '1946-05-29', 'age': datetime.now().year - 1946, 'dr_id': 1, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data2 = {'patient_id': 2, 'sex': 0, 'birthdate': '1970-03-09', 'age': datetime.now().year - 1970, 'dr_id': 1, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data3 = {'patient_id': 3, 'sex': 0, 'birthdate': '1945-10-08', 'age': datetime.now().year - 1945, 'dr_id': 1, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data4 = {'patient_id': 4, 'sex': 1, 'birthdate': '1939-05-23', 'age': datetime.now().year - 1939, 'dr_id': 0, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data5 = {'patient_id': 5, 'sex': 1, 'birthdate': '1943-12-11', 'age': datetime.now().year - 1943, 'dr_id': 0, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data6 = {'patient_id': 6, 'sex': 1, 'birthdate': '1960-02-23', 'age': datetime.now().year - 1960, 'dr_id': 1, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data7 = {'patient_id': 7, 'sex': 0, 'birthdate': '1939-10-03', 'age': datetime.now().year - 1939, 'dr_id': 0, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data8 = {'patient_id': 8, 'sex': 0, 'birthdate': '1935-06-21', 'age': datetime.now().year - 1935, 'dr_id': 0, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}
patient_data9 = {'patient_id': 9, 'sex': 1, 'birthdate': '1966-04-15', 'age': datetime.now().year - 1966, 'dr_id': 1, 'data_id': -1, 'date': str(datetime.now()), 'critical':-1, 'heart_rate': -1, 'glucose': -1, 'temperature': -1, 'blood_pressure': -1, 'fall': -1, 'location':'N/A'}


#Machine learning setup

data = pd.read_csv("/home/pi/Desktop/BEKY/BEKY_sensors_uno/heart.csv") 
used_cols = ["age", "sex", "trestbps", "fbs", "restecg"]  # blood pressure, fasting blood sugar, heart rate
X = data[used_cols]
y = data["target"]
knn = KNeighborsClassifier(n_neighbors=7, weights="distance")
knn.fit(X, y)

def prediction(patient_data):
    attributes = ["age", "sex", "blood_pressure", "glucose", "heart_rate"]
    patient_data_prediction = []
    for i in attributes:
        patient_data_prediction.append(patient_data[i])
    critical = knn.predict([patient_data_prediction])
    patient_data['critical'] = critical[0]
    print('After prediction\n')
    print(patient_data)

patient_id = 0
while 1:
    salt = os.urandom(16) # In Bytes
    iv = os.urandom(16) # In Bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
            iterations=100000,
        backend=default_backend()
        )
    key = kdf.derive(password)
    # if you use AES the key should be in bytes not in Base 64
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    #patient_id = randint(0,9)
    hour = datetime.now().hour
    minute = datetime.now().minute
    #print(ser.readline().decode())
    data_list = ser.readline().decode(errors='ignore').split(":")
    fieldname = data_list[0]
    value = data_list[1]
    print('fieldname: '+fieldname+' // value: '+value)
    patient_data = eval('patient_data'+str(patient_id))
    if fieldname in ['temperature' , 'glucose' , 'blood_pressure' , 'heart_rate' , 'fall']:
        loc=parseGPS(serialGPS.readline().decode(errors='ignore'))
        #print(loc)
        if loc != None and loc != 'Lat:   -- Lon:   -- Altitude: None M':           
            patient_data['location']=loc
            #print(loc)
            patient_data = patient_access(patient_data, fieldname, value)
        else:
            patient_data = patient_access(patient_data, fieldname, value)
    if (patient_data['temperature'] != -1
        and patient_data['glucose'] != -1
        and patient_data['blood_pressure'] != -1
        and patient_data['heart_rate'] != -1
        and patient_data['fall'] != -1):
        patient_id = patient_id + 1
        if patient_id ==10:
            patient_id =0
        print('\nPrediction + Handling data\n')
        handle_data(patient_data)
        
client.loop_forever()