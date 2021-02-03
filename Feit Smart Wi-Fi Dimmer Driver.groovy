/**
 * Copyright 2021 Miguel Adame Gurrola
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

metadata {
	definition(name: "Feit Smart Wi-Fi Dimmer Driver", namespace: "mixeladm", author: "Miguel Adame") {
		capability "Actuator"
		capability "Switch"
		capability "Sensor"
        capability "Switch Level"

		command "status"
	}
}

preferences {
	section("Device Configuration") {
		input "ipaddress", "text", title: "Device IP Address:", required: false
		input "devId", "text", title: "Device ID:", required: false
		input "localKey", "text", title: "Device local key:", required: false
        input name: "logging", type: "bool", title: "Enable debug logging", defaultValue: true
        
	}
}

def logsOff() {
	log.warn "debug logging disabled..."
	device.updateSetting("logging", [value: "false", type: "bool"])
}

def updated() {
    
	log.info "updated..."
	log.warn "debug logging is: ${logging == true}"
	sendEvent(name: "switch", value: "off")
    
}

def processResponse(def response) {
    Logging ("Input from Device: $response")
    def jsonSlurper = new groovy.json.JsonSlurper()
    def status_object = jsonSlurper.parseText(response)
    
    //Is light on?  DPS 1
    Logging ( status_object.dps["1"])
    if (status_object.dps["1"] == true) {
        sendEvent(name: "switch", value : "on", isStateChange : true)
    } else {
        sendEvent(name: "switch", value : "off", isStateChange : true)
    }
    
    //Device level DPS 2
    if (status_object.dps["2"] ){
        sendEvent(name: "level", value : status_object.dps["2"]/10, isStateChange : true)
    }
}

def parse(String input) {
    
	Logging ("Entering parsing...")
	Logging ("$input")
    
    //convert to byteAray and drop the control bytes (unless you really wanna validate the message...)
	byte[] msg_byte = hubitat.helper.HexUtils.hexStringToByteArray(input) 
    msg_byte = msg_byte[20..-9] 
    
	String status = new String(msg_byte )
   
    //Decrypt without Base64
    status = decrypt(msg_byte, settings.localKey, false)     
    processResponse(status)
    
	try {
		interfaces.rawSocket.close()
	} catch (e) {
		log.error "Could not close socket: $e"
	}
}


def payload()
{
  
	def payload_dict = [
		"device": [
			"control": [
				"hexByte": "07",
				"command": ["devId":"", "uid": "", "t": ""],
			],
            "dp_query": [
                "hexByte": "0a",
                "command": ["gwId": "", "devId": "", "uid": "", "t": ""]
             ],
			"prefix": "000055aa00000000000000",
			"suffix": "000000000000aa55",
            "3_3header": "332E33000000000000000000000000"
            
		]
	]

	return payload_dict
}


import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher


def encrypt (def plainText, def secret, def base64 = true) {

	def cipher = Cipher.getInstance("AES/ECB/PKCS5Padding ")
	SecretKeySpec key = new SecretKeySpec(secret.getBytes("UTF-8"), "AES")
	cipher.init(Cipher.ENCRYPT_MODE, key)
    
	def result = cipher.doFinal(plainText.getBytes("UTF-8"))
    //version 3.3 does not use base64 but ver 3.1 does
    if (base64) result = result.encodeBase64().toString()

	return result
}


def decrypt (def cypherText, def secret, def base64 = true) {

    byte[] decodedBytes = cypherText
    //version 3.3 does not use base64
    if (base64)  decodedBytes =  cypherText.decodeBase64()

	def cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
	SecretKeySpec key = new SecretKeySpec(secret.getBytes("Latin1"), "AES")
	cipher.init(Cipher.DECRYPT_MODE, key)

	return new String(cipher.doFinal(decodedBytes), "UTF-8")
}

import java.security.MessageDigest

def generateMD5(String s){
	MessageDigest.getInstance("MD5").digest(s.bytes).encodeHex().toString()
}

def CRC32b(bytes, length) {
	crc = 0xFFFFFFFF

	for (i = 0; i < length; i++) {
		b = Byte.toUnsignedInt(bytes[i])

		crc = crc ^ b
		for (j = 7; j >= 0; j--) {
			mask = -(crc & 1)
			crc = (crc >> 1) ^(0xEDB88320 & mask)
		}
	}

	return ~crc
}

/*
def optionalSet(name, value){
   if (json_data.containsKey("gwId")) {
		json_data["gwId"] = settings.devId
	} 
}
*/

def generate_payload(command, data=null) {

	json_data = payload()["device"][command]["command"]

    //
	if (json_data.containsKey("gwId")) json_data["gwId"] = settings.devId
    //all the commands use those 2
    json_data["devId"] = settings.devId
    json_data["uid"] = settings.devId
    
	//also, we always send Time
	Date now = new Date()
	json_data["t"] =  (now.getTime()/1000).toInteger().toString()
	
	if (data != null) {
		json_data["dps"] = data
	}
     
    
    def json = new groovy.json.JsonBuilder()
    json json_data
    
	json_payload = groovy.json.JsonOutput.toJson(json.toString())
	json_payload = json_payload.replaceAll("\\\\", "")
    json_payload = json_payload.replaceFirst(" ", "")
	json_payload = json_payload[1..-2]

	Logging ("Plain text command: $json_payload")

    //Tuya Version 3.3

    json_payload = hubitat.helper.HexUtils.byteArrayToHexString( encrypt(json_payload, settings.localKey,false))
    //for commands only
    if (payload()["device"][command]["hexByte"] != "0a") json_payload = payload()["device"]["3_3header"] + json_payload

    json_payload = hubitat.helper.HexUtils.hexStringToByteArray(json_payload+ payload()["device"]["suffix"] )        

    def pre = payload()["device"]["prefix"] + payload()["device"][command]["hexByte"] + "000000" + Integer.toHexString(json_payload.size())
    
    //Put together all the data
    ByteArrayOutputStream output = new ByteArrayOutputStream()
    output.write(hubitat.helper.HexUtils.hexStringToByteArray(pre))
    output.write(json_payload)
    

    byte[] buf = output.toByteArray()
    //calculate the CRC
    crc32 = CRC32b(buf, buf.size()-8) & 0xffffffff
    hex_crc = Long.toHexString(crc32)
    crc_bytes = hubitat.helper.HexUtils.hexStringToByteArray(hex_crc)
    //replace the CRC bytes
    for(i=0;i<=3;i++) buf[buf.size()-(8-i)] = crc_bytes[i]

    return buf     
    
}

import hubitat.device.HubAction
import hubitat.device.Protocol

//raw send...
def sendMessage(def msg){
    //open the socket and send the message
    interfaces.rawSocket.connect(settings.ipaddress, 6668, byteInterface:true, readDelay: 150) 
    interfaces.rawSocket.sendMessage(msg)
    
    //debug
    Logging (msg)
}



//send a command message
def sendSetMessage(def dps) {

    byte[] buf = generate_payload("control", dps)
	String msg = hubitat.helper.HexUtils.byteArrayToHexString(buf)
	sendMessage(msg) 
    
	runInMillis(50, status, [overwrite:true, missfire:"ignore"]) 
    
}

def on() {
    
    //turn on the light
    Logging ("Sending ON message")
    sendSetMessage([1:true])
    sendEvent(name: "switch", value : "on", isStateChange : true)
    
}

def off() {
    
    //turn off the light
    Logging ("Sending OFF message") 
    sendSetMessage([1:false])
    sendEvent(name: "switch", value : "off", isStateChange : true)
     
    
}

def setLevel(int level, transition = null) {
    
    Logging ("setLevel: level = ${level}" )
    //we need to calculate the real level between 1 and 1000
	level = 1000 * (level / 100)
	if (level < 10) { level = 10 } 
	if (level > 1000) { level = 1000 } 
    
    sendSetMessage([1:true, 2:level]) 
    sendEvent(name: "level", value : level/10, isStateChange : true)
    sendEvent(name: "switch", value : "on", isStateChange : true)
}

//ask the device status
def status() {
    
    Logging ("Sending status message")
	byte[] buf = generate_payload("dp_query")    
	String msg = hubitat.helper.HexUtils.byteArrayToHexString(buf)
    sendMessage(msg)    

}

def Logging(def msg){
 if (logging) log.debug msg
}
