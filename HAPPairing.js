var crypto = require("crypto");
var srp = require("srp");
var ed25519 = require("ed25519");
var hkdf = require("./util/hkdf");
var tlv = require("./util/tlv");
var encryption = require("./util/encryption");
var uuid = require('./util/uuid');
var HTTPClient = require('./EventedHTTPClient').EventedHTTPClient;
var debug = require('debug')('Pairing');
var leftpad = require('./util/leftpad');


// Various "type" constants for HAP's TLV encoding.
HAPClient_Types = {
    REQUEST_TYPE: 0x00,
    USERNAME: 0x01,
    SALT: 0x02,
    PUBLIC_KEY: 0x03,
    PASSWORD_PROOF: 0x04,
    ENCRYPTED_DATA: 0x05,
    SEQUENCE_NUM: 0x06,
    ERROR_CODE: 0x07,
    PROOF: 0x0a
}

module.exports = {
    AccessoryData: AccessoryData,
    HAPtoAccessoryPairing: HAPtoAccessoryPairing
}

function AccessoryData() {
    this.PairProcess = null;
    this.my_username = null;
    this.my_privateKey = null;
    this.my_publicKey = null;
    this.acc_username = null;
    this.acc_publicKey = null;
    this.acc_mdnsname = null;
    this.acc_lastip = null;
    this.acc_lastport = null;
    this.acc_pin = null;
    this.last_paired = null;
}

function HAPtoAccessoryPairing() {
    var mytest = '';
}
HAPtoAccessoryPairing.prototype._PairAccessory_Step1 = function (PairingData) {
    //Create and send the starter packet
    var that = this;
    var outTLV = tlv.encode(HAPClient_Types.REQUEST_TYPE, 0, HAPClient_Types.SEQUENCE_NUM, 1);
    debug("Sending P-S 1");
    PairingData.connection.HTTPCommand('POST', '/pair-setup', outTLV, (function (response) { that._PairAccessory_Step2(response, PairingData); }));
}
HAPtoAccessoryPairing.prototype._PairAccessory_Step2 = function (response, PairingData) { //Send initial Public Key ?used for pairing only?
    var that = this;
    if (response.headers['content-type'] != 'application/pairing+tlv8') return;
    debug("Received P-S 2");

    //Receive accessory's Salt and Public Key.
    var inTLV = tlv.decode(response.data);
    var acc_salt = new Buffer(inTLV[HAPClient_Types.SALT]);
    var acc_public_key = new Buffer(inTLV[HAPClient_Types.PUBLIC_KEY]);

    //Generate a new Key
    srp.genKey(32, function (error, key) {
        PairingData.srp = new srp.Client(srp.params["3072"], Buffer(acc_salt), Buffer("Pair-Setup"), Buffer(PairingData.acc_pin), key);
        PairingData.srp.setB(acc_public_key);
        var outTLV = tlv.encode(HAPClient_Types.SEQUENCE_NUM, inTLV[HAPClient_Types.SEQUENCE_NUM][0] + 1,
            HAPClient_Types.PUBLIC_KEY, PairingData.srp.computeA(),
            HAPClient_Types.PASSWORD_PROOF, PairingData.srp.computeM1());
        debug("Sending P-S 3");
        PairingData.connection.HTTPCommand('POST', '/pair-setup', outTLV, (function (response) { that._PairAccessory_Step3(response, PairingData); }));
    })
};
HAPtoAccessoryPairing.prototype._PairAccessory_Step3 = function (response, PairingData) {
    var that = this;
    if (response.headers['content-type'] != 'application/pairing+tlv8') return;
    var inTLV = tlv.decode(response.data);
    debug("Received P-S 4");

    //Verify the Server Password Proof is Valid
    PairingData.srp.checkM2(inTLV[HAPClient_Types.PASSWORD_PROOF]);

    //Generate all of the signing keys for Verification
    var PairingEncryption = hkdf.HKDF("sha512", Buffer("Pair-Setup-Encrypt-Salt"), PairingData.srp.computeK(), Buffer("Pair-Setup-Encrypt-Info"), 32);
    var keys_ControllerSign = hkdf.HKDF("sha512", Buffer("Pair-Setup-Controller-Sign-Salt"), PairingData.srp.computeK(), Buffer("Pair-Setup-Controller-Sign-Info"), 32);

    //This is the Encryption key information used for communication
    var seed = crypto.randomBytes(32);
    var keyPair = ed25519.MakeKeypair(seed);
    PairingData.my_privateKey = keyPair.privateKey;
    PairingData.my_publicKey = keyPair.publicKey;

    //Generate the Server Proof so the Accessory can ensure we have our own private key
    var material = Buffer.concat([keys_ControllerSign, Buffer(PairingData.my_username), PairingData.my_publicKey]);
    var serverProof = ed25519.Sign(material, Buffer(PairingData.my_privateKey));

    //This is the message we are sending back to the server
    var message = tlv.encode(
        HAPClient_Types.USERNAME, PairingData.my_username,
        HAPClient_Types.PUBLIC_KEY, PairingData.my_publicKey,
        HAPClient_Types.PROOF, serverProof
    );

    //Encrypt and sign the message
    var ciphertextBuffer = Buffer(Array(message.length));
    var macBuffer = Buffer(Array(16));
    encryption.encryptAndSeal(PairingEncryption, Buffer("PS-Msg05"), message, null, ciphertextBuffer, macBuffer);

    //Package up the encryption in a TLV
    var outTLV = tlv.encode(
        HAPClient_Types.SEQUENCE_NUM, 0x05,
        HAPClient_Types.ENCRYPTED_DATA, Buffer.concat([ciphertextBuffer, macBuffer])
    );
    debug("Sending P-S 5");
    //Send this to the server
    PairingData.connection.HTTPCommand('POST', '/pair-setup', outTLV, (function (response) { that._PairAccessory_Step4(response, PairingData); }));
};
HAPtoAccessoryPairing.prototype._PairAccessory_Step4 = function (response, PairingData) {
    var that = this;
    if (response.headers['content-type'] != 'application/pairing+tlv8') return;
    debug("Received P-S 6");

    var inTLV = tlv.decode(response.data);
    var encryptedData = inTLV[HAPClient_Types.ENCRYPTED_DATA];

    //Generate Signing Keys For Verification
    var PairingEncryption = hkdf.HKDF("sha512", Buffer("Pair-Setup-Encrypt-Salt"), PairingData.srp.computeK(), Buffer("Pair-Setup-Encrypt-Info"), 32);
    var keys_AccessorySign = hkdf.HKDF("sha512", Buffer("Pair-Setup-Accessory-Sign-Salt"), PairingData.srp.computeK(), Buffer("Pair-Setup-Accessory-Sign-Info"), 32);

    //Decrypt the packet
    var messageData = Buffer(encryptedData.length - 16);
    var authTagData = Buffer(16);
    encryptedData.copy(messageData, 0, 0, encryptedData.length - 16);
    encryptedData.copy(authTagData, 0, encryptedData.length - 16, encryptedData.length);
    var plaintextBuffer = Buffer(messageData.length);
    encryption.verifyAndDecrypt(PairingEncryption, Buffer("PS-Msg06"), messageData, authTagData, null, plaintextBuffer);
    //End Decryption

    // decode the client payload and pass it on to the next step
    var M5Packet = tlv.decode(plaintextBuffer);

    PairingData.acc_username = M5Packet[HAPClient_Types.USERNAME];
    PairingData.acc_publicKey = M5Packet[HAPClient_Types.PUBLIC_KEY];
    var accessory_proof = M5Packet[HAPClient_Types.PROOF];

    //Verify Proof
    var completeData = Buffer.concat([keys_AccessorySign, PairingData.acc_username, PairingData.acc_publicKey]);

    if (!ed25519.Verify(completeData, accessory_proof, PairingData.acc_publicKey)) {
        debug("[%s] Invalid signature", this.accessoryInfo.username);

        return;
    }
    debug("P-S Done");
    //This completes the pairing process
    PairingData.srp = null;

    //Move on to the next step (Verify the Pairing)
    PairingData.PairProcess.VerifyAccessoryPairing(PairingData);

};
HAPtoAccessoryPairing.prototype.PairAccessory = function (PairingData) { //Start the Pairing Process
    //Create the Web Connection
    var that = this;
    this.PairingData = PairingData;
    PairingData.connection = new HTTPClient(PairingData.acc_lastip, PairingData.acc_lastport)
    PairingData.connection.InitializeProxy(PairingData, (function (PairingData) { that._PairAccessory_Step1(that.PairingData); }));
}

HAPtoAccessoryPairing.prototype.VerifyAccessoryPairing = function (PairingData) {
    //Generate a key for the Verification Process
    var that = this;
    PairingData.Verify = {};
    PairingData.Verify.my_secretKey = encryption.generateCurve25519SecretKey();
    PairingData.Verify.my_publicKey = encryption.generateCurve25519PublicKeyFromSecretKey(PairingData.Verify.my_secretKey);

    //Create the Web Connection
    if (!PairingData.connection) {
        PairingData.connection = new webclient;
    } else {


        //Create and send the starter packet
        var outTLV = tlv.encode(HAPClient_Types.PUBLIC_KEY, PairingData.Verify.my_publicKey, HAPClient_Types.SEQUENCE_NUM, 1);
        debug("Sending P-V 1");
        PairingData.connection.HTTPCommand('POST', '/pair-verify', outTLV, (function (response) { that._VerifyAccessoryPairing_Step2(response, PairingData); }));
    }
}
HAPtoAccessoryPairing.prototype._VerifyAccessoryPairing_Step2 = function (response, PairingData) {
    var that = this;
    var inTLV = tlv.decode(response.data);
    debug("Received P-V 2");
    PairingData.Verify.acc_publicKey = inTLV[HAPClient_Types.PUBLIC_KEY];

    //Now that we have the Public Key we can generate the shared secret and signing key for Verification.
    PairingData.Verify.sharedSec = encryption.generateCurve25519SharedSecKey(PairingData.Verify.my_secretKey, PairingData.Verify.acc_publicKey);
    PairingData.Verify.signingKey = hkdf.HKDF("sha512", Buffer("Pair-Verify-Encrypt-Salt"), PairingData.Verify.sharedSec, Buffer("Pair-Verify-Encrypt-Info"), 32).slice(0, 32);

    //Populate the HAPEncryption Object
    PairingData.Verify.enc = new HAPEncryption();
    PairingData.Verify.enc.clientPublicKey = PairingData.Verify.acc_publicKey;
    PairingData.Verify.enc.secretKey = PairingData.Verify.my_secretKey;
    PairingData.Verify.enc.publicKey = PairingData.Verify.my_publicKey;
    PairingData.Verify.enc.sharedSec = PairingData.Verify.sharedSec;
    PairingData.Verify.enc.hkdfPairEncKey = PairingData.Verify.signingKey;

    //Decrypt the packet
    var encryptedData = inTLV[HAPClient_Types.ENCRYPTED_DATA];
    var messageData = Buffer(encryptedData.length - 16);
    var authTagData = Buffer(16);
    encryptedData.copy(messageData, 0, 0, encryptedData.length - 16);
    encryptedData.copy(authTagData, 0, encryptedData.length - 16, encryptedData.length);
    var plaintextBuffer = Buffer(messageData.length);
    encryption.verifyAndDecrypt(PairingData.Verify.signingKey, Buffer("PV-Msg02"), messageData, authTagData, null, plaintextBuffer);
    //End Decryption

    var decryptedTLV = tlv.decode(plaintextBuffer);

    //Verify the Username matches what 
    PairingData.Verify.acc_username = decryptedTLV[HAPClient_Types.USERNAME];
    if (Buffer.compare(Buffer(PairingData.acc_username), Buffer(PairingData.Verify.acc_username)) < 0)
        debug("Usernames don't match");
    var accessoryProof = decryptedTLV[HAPClient_Types.PROOF];

    //Verify the Accessory's Proof
    var accessoryMaterial = Buffer.concat([PairingData.Verify.enc.clientPublicKey, PairingData.Verify.acc_username, PairingData.Verify.enc.publicKey]);
    if (!ed25519.Verify(accessoryMaterial, accessoryProof, Buffer(PairingData.acc_publicKey))) {
        debug("[%s] Client %s provided an invalid signature", this.accessoryInfo.username, clientUsername);
        return;
    }

    //Generate our proof to send to the server that we know our private key for data transmission.
    var myMaterial = Buffer.concat([PairingData.Verify.enc.publicKey, Buffer(PairingData.my_username), PairingData.Verify.enc.clientPublicKey]);
    var a = myMaterial;
    var b = PairingData.my_privateKey;

    var serverProof = ed25519.Sign(myMaterial, PairingData.my_privateKey);

    var message = tlv.encode(
        HAPClient_Types.USERNAME, PairingData.my_username,
        HAPClient_Types.PROOF, serverProof);

    // encrypt the response
    var ciphertextBuffer = Buffer(Array(message.length));
    var macBuffer = Buffer(Array(16));
    encryption.encryptAndSeal(PairingData.Verify.signingKey, Buffer("PV-Msg03"), message, null, ciphertextBuffer, macBuffer);

    //Create and send the response packet
    var outTLV = tlv.encode(HAPClient_Types.SEQUENCE_NUM, 0x03,
        HAPClient_Types.ENCRYPTED_DATA, Buffer.concat([ciphertextBuffer, macBuffer]));
    debug("Sending P-V 3");
    PairingData.connection.HTTPCommand('POST', '/pair-verify', outTLV, (function (response) { that._VerifyAccessoryPairing_Step3(response, PairingData); }));
    //PairingData.connection.HTTPCommand('GET', '/accessories', outTLV, (function (response) { _VerifyAccessoryPairing_Step3(response, PairingData); }));
};
HAPtoAccessoryPairing.prototype._VerifyAccessoryPairing_Step3 = function (response, PairingData) {
    var that = PairingData;
    var inTLV = tlv.decode(response.data);
    debug("Received P-V 4");

    // now that the client has been verified, we must "upgrade" our pesudo-HTTP connection to include
    // TCP-level encryption. We'll do this by adding some more encryption vars to the session, and using them
    // in future calls to onEncrypt, onDecrypt.

    var encSalt = new Buffer("Control-Salt");
    var infoRead = new Buffer("Control-Read-Encryption-Key");
    var infoWrite = new Buffer("Control-Write-Encryption-Key");

    PairingData.Verify.enc.accessoryToControllerKey = hkdf.HKDF("sha512", encSalt, PairingData.Verify.enc.sharedSec, infoRead, 32);
    PairingData.Verify.enc.controllerToAccessoryKey = hkdf.HKDF("sha512", encSalt, PairingData.Verify.enc.sharedSec, infoWrite, 32);
    PairingData.connection.on("encrypt",
        function (data, encrypted, session) {
            var enc = that.Verify.enc;
            encrypted.data = encryption.layerEncrypt(data, enc.controllerToAccessoryCount, enc.controllerToAccessoryKey);
        });
    PairingData.connection.on("decrypt",
        function (data, decrypted, session) {
            var enc = that.Verify.enc;
            decrypted.data = encryption.layerDecrypt(data, enc.accessoryToControllerCount, enc.accessoryToControllerKey);
        });

    //this.emit('encrypt', data, encrypted, this._session);
    //Request the Accessories List
    console.log('Pairing Complete');
    this.GetAccessories(PairingData);
};
HAPtoAccessoryPairing.prototype.GetAccessories = function (PairingData) {
    PairingData.connection.HTTPCommand('GET', '/accessories', null, (function (response) {
        var accessoryObject = JSON.parse(response.data.toString());
        var Service = require("hap-nodejs").Service;
        var Characteristic = require("hap-nodejs").Characteristic;

        console.log("Done");
        var myLine = '';
        myLine += "<html><head></head><body><table border=1>";
        myLine += "<tr><td>Accessory</td><td colspan=2>Service</td><td colspan=4>Characteristic</td></tr>";
        myLine += "<tr><td>ID</td><td>ID</td><td>Name</td><td>ID</td><td>Name</td><td>Format</td><td>Value</td></tr>";
        for (i = 0; i < accessoryObject.accessories.length; i++) {
            var myAccessory = accessoryObject.accessories[i];
            getAccessoryFromHAP(myAccessory);
        }
        myLine += "</table></body></html>";
        require('fs').writeFileSync("/Users/paullovelace/homebridge/node_modules/homebridge-HAP/test.html", myLine);

        console.log(myLine);

        function getServiceName(uuid) {
            for (var myService in Service) {
                var myItem = new Service[myService];
                myItem = myItem;
                if (myItem.UUID == uuid)
                    return myService;
            }
            //Object.keys(Characteristic)
            return 'Unknown';
        }

        function getCharacteristicName(uuid) {
            for (var myCharacteristic in Characteristic) {
                if (!(myCharacteristic == 'Formats' || myCharacteristic == 'Units' || myCharacteristic == 'Perms')) {
                    var myItem = new Characteristic[myCharacteristic];
                    myItem = myItem;
                    if (myItem.UUID == uuid)
                        return myCharacteristic;
                }
            }
            //Object.keys(Characteristic)
            return 'Unknown';

        }

        function getAccessoryFromHAP(myAccessory) {
            for (j = 0; j < myAccessory.services.length; j++) {
                var myService = myAccessory.services[j];
                getServiceFromHAP(myService, myAccessory);
            }
        }

        function getServiceFromHAP(myService, myAccessory) {
            for (k = 0; k < myService.characteristics.length; k++) {
                var myCharacteristic = myService.characteristics[k];
                getCharacteristicFromHAP(myCharacteristic, myService, myAccessory);
            }
        }

        function getCharacteristicFromHAP(myCharacteristic, myService, myAccessory) {
            var ServiceName = getServiceName(leftpad(myService.type, 8, '0') + "-0000-1000-8000-0026BB765291");
            var CharacteristicName = getCharacteristicName(leftpad(myCharacteristic.type, 8, '0') + "-0000-1000-8000-0026BB765291");
            myLine += '<tr>';
            myLine += "<td>" + myAccessory.aid + "</td>";
            myLine += "<td>" + myService.iid + "</td>";
            myLine += "<td>" + ServiceName + "</td>";
            myLine += "<td>" + myCharacteristic.iid + "</td>";
            myLine += "<td>" + CharacteristicName + "</td>";
            myLine += "<td>" + myCharacteristic.format + "</td>";
            if (myCharacteristic.format == 'tlv8') {
                if (!myCharacteristic.value) {
                    myLine += "<td>" + myCharacteristic.value + "</td>";
                } else if (CharacteristicName == 'StreamingStatus') {
                    myLine += getTLVhtmlDef(Buffer(myCharacteristic.value, 'base64'), StreamController.SetupTypes, (function (myIdx, myData) { return getEnumName(myData.readUInt8(0), StreamController.StreamingStatus); }));
                } else if (CharacteristicName == 'SelectedStreamConfiguration') {
                    myLine += getTLVhtml(Buffer(myCharacteristic.value, 'base64'),  
                                (function (myIdx, myData) { 
                                    return displaySelectedStreamConfiguration(myIdx, myData); 
                                    }));
                } else if (CharacteristicName == 'SetupEndpoints') {
                    myLine += getTLVhtmlDef(Buffer(myCharacteristic.value, 'base64'), StreamController.SetupTypes,  
                                (function (myIdx, myData) { 
                                    return displaySetupEndpoint(myIdx, myData); 
                                    }));
                } else if (CharacteristicName == 'SupportedVideoStreamConfiguration') {
                    myLine += getTLVhtmlDef(Buffer(myCharacteristic.value, 'base64'), StreamController.SetupTypes,  
                                (function (myIdx, myData) { 
                                    return getTLVhtml(myData); 
                                    }));
                } else if (CharacteristicName == 'SupportedAudioStreamConfiguration') {
                    myLine += getTLVhtmlDef(Buffer(myCharacteristic.value, 'base64'), StreamController.SetupTypes,  
                                (function (myIdx, myData) { 
                                    return getTLVhtml(myData); 
                                    }));
                } else if (CharacteristicName == 'SupportedRTPConfiguration') {
                    myLine += getTLVhtmlDef(Buffer(myCharacteristic.value, 'base64'), StreamController.RTPConfigTypes);
                } else {
                    myLine += getTLVhtml(Buffer(myCharacteristic.value, 'base64'));
                }

            } else {
                myLine += "<td colspan=2>" + myCharacteristic.value + "</td>";
            }
            myLine += "</tr>";
        }

        function getTLVhtmlDef(myRawTLV, DefinitionObject, valueRenderer) {
            var inTLV = tlv.decode(myRawTLV);
            myPart = '<td><table border=1>';
            for (var myID in inTLV) {
                myIdx = getEnumName(parseInt(myID), DefinitionObject);
                if (!valueRenderer)
                    myPart += '<tr><td>' + myID + ' (' + myIdx + ')</td><td>' + inTLV[myID].toString('hex') + '</td></tr>';
                else
                    myPart += '<tr><td>' + myID + ' (' + myIdx + ')</td><td>' + valueRenderer(parseInt(myID), inTLV[myID]) + '</td></tr>';
            }

            myPart += '</table></td>'
            return myPart;
        }

        function getEnumName(myData, DefinitionObject) {
            for (var myIdx in DefinitionObject)
                if (DefinitionObject[myIdx] == myData)
                    return myIdx;
        }

        function displaySelectedStreamConfiguration(myID, myData){
            return getTLVhtml(myData);
        }

        function displaySetupEndpoint(myID, myData){
            switch(myID) {
                case 1:
                    return myData.toString('hex');
                case 2:
                    return getEnumName(myData.readUInt8(0), StreamController.SetupStatus);
                case 3:
                    return getTLVhtmlDef(myData, StreamController.SetupAddressInfo, displaySetupIP);
                case 4: case 5:
                    return getTLVhtmlDef(myData, StreamController.SetupSRTP_PARAM)
                case 6: case 7:
                    return myData.readUInt32LE(0);
                default:
                    return getTLVhtml(myData);
            }
            
        }
        function displaySetupIP (myID, myData){
            switch(myID) {
                case StreamController.SetupAddressInfo.ADDRESS_VER:
                    return myData.readUInt8(0);
                case StreamController.SetupAddressInfo.ADDRESS:
                    return myData.toString();
                case StreamController.SetupAddressInfo.VIDEO_RTP_PORT:
                case StreamController.SetupAddressInfo.AUDIO_RTP_PORT:
                    return myData.readUInt16LE(0);
                default: 
                    return myData.toString();
            }
        }
        

        function getTLVhtml(myRawTLV, valueRenderer) {
            var inTLV = tlv.decode(myRawTLV);
            myPart = '<td><table border=1>';
            for (var myID in inTLV) {
                if (!valueRenderer)
                    myPart += '<tr><td>' + myID + '</td><td>' + inTLV[myID].toString('hex') + '</td></tr>';
                else
                    myPart += '<tr><td>' + myID + '</td><td>' + valueRenderer(parseInt(myID), inTLV[myID]) + '</td></tr>';
            }
            myPart += '</table></td>'
            return myPart;
        }
    }));
};




function HAPEncryption() {
    // initialize member vars with null-object values
    this.clientPublicKey = new Buffer(0);
    this.secretKey = new Buffer(0);
    this.publicKey = new Buffer(0);
    this.sharedSec = new Buffer(0);
    this.hkdfPairEncKey = new Buffer(0);
    this.accessoryToControllerCount = { value: 0 };
    this.controllerToAccessoryCount = { value: 0 };
    this.accessoryToControllerKey = new Buffer(0);
    this.controllerToAccessoryKey = new Buffer(0);
}

var StreamController = {};
StreamController.SetupTypes = {
    SESSION_ID: 0x01,
    STATUS: 0x02,
    ADDRESS: 0x03,
    VIDEO_SRTP_PARAM: 0x04,
    AUDIO_SRTP_PARAM: 0x05,
    VIDEO_SSRC: 0x06,
    AUDIO_SSRC: 0x07
}

StreamController.SetupStatus = {
    SUCCESS: 0x00,
    BUSY: 0x01,
    ERROR: 0x02
}

StreamController.SetupAddressVer = {
    IPV4: 0x00,
    IPV6: 0x01
}

StreamController.SetupAddressInfo = {
    ADDRESS_VER: 0x01,
    ADDRESS: 0x02,
    VIDEO_RTP_PORT: 0x03,
    AUDIO_RTP_PORT: 0x04
}

StreamController.SetupSRTP_PARAM = {
    CRYPTO: 0x01,
    MASTER_KEY: 0x02,
    MASTER_SALT: 0x03
}

StreamController.StreamingStatus = {
    AVAILABLE: 0x00,
    STREAMING: 0x01,
    BUSY: 0x02
}

StreamController.RTPConfigTypes = {
    CRYPTO: 0x02
}

StreamController.SRTPCryptoSuites = {
    AES_CM_128_HMAC_SHA1_80: 0x00,
    AES_CM_256_HMAC_SHA1_80: 0x01,
    NONE: 0x02
}

StreamController.VideoTypes = {
    CODEC: 0x01,
    CODEC_PARAM: 0x02,
    ATTRIBUTES: 0x03
}

StreamController.VideoCodecTypes = {
    H264: 0x00
}

StreamController.VideoCodecParamTypes = {
    PROFILE_ID: 0x01,
    LEVEL: 0x02,
    PACKETIZATION_MODE: 0x03,
    CVO_ENABLED: 0x04,
    CVO_ID: 0x05
}

StreamController.VideoCodecParamCVOTypes = {
    UNSUPPORTED: 0x01,
    SUPPORTED: 0x02
}

StreamController.VideoCodecParamProfileIDTypes = {
    BASELINE: 0x00,
    MAIN: 0x01,
    HIGH: 0x02
}

StreamController.VideoCodecParamLevelTypes = {
    TYPE3_1: 0x00,
    TYPE3_2: 0x01,
    TYPE4_0: 0x02
}

StreamController.VideoCodecParamPacketizationModeTypes = {
    NON_INTERLEAVED: 0x00
}

StreamController.VideoAttributesTypes = {
    IMAGE_WIDTH: 0x01,
    IMAGE_HEIGHT: 0x02,
    FRAME_RATE: 0x03
}
