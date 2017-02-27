var pairing = require('./HAPPairing').HAPtoAccessoryPairing;
var http = require('http');
var mdns = require('mdns');
var Accessory, Service, Characteristic, UUIDGen;
var uuid = require('./util/uuid');

module.exports = function(homebridge) {
  console.log("homebridge API version: " + homebridge.version);

  // Accessory must be created from PlatformAccessory Constructor
  Accessory = homebridge.platformAccessory;

  // Service and Characteristic are from hap-nodejs
  Service = homebridge.hap.Service;
  Characteristic = homebridge.hap.Characteristic;
  UUIDGen = homebridge.hap.uuid;
  
  // For platform plugin to be considered as dynamic platform plugin,
  // registerPlatform(pluginName, platformName, constructor, dynamic), dynamic must be true
    homebridge.registerPlatform("homebridge-HomeKit", "HomeKit", HomeKitPlatform, true);
}

// Platform constructor
// config may be null
// api may be null if launched from old homebridge version
function HomeKitPlatform(log, config, api) {
  log("HomeKitPlatform Init");
  var platform = this;
  this.log = log;
  this.config = config;
  this.accessories = [];
  
  // Save the API object as plugin needs to register new accessory via this object.
  this.api = api;
  
  //Create a way to track items in the browser
  this.mdnsAccessories=[];

  //Create a way to track accessories provided from homebridge
  this.priorAccessories=[];

  // Listen to event "didFinishLaunching", this means homebridge already finished loading cached accessories
  // Platform Plugin should only register new accessory that doesn't exist in homebridge after this event.
  // Or start discover new accessories
  this.api.on('didFinishLaunching', function() {
    var browser = mdns.createBrowser('_hap._tcp'); 
    browser.on('serviceUp', function(info, flags) { 
        console.log("HomeKit Accessory Found:  "+info.name);
        if (platform.config.HAPAccessories[info.name]!==undefined)
            InitializeAccessory({ "Name" : info.name, "IP":info.addresses[info.addresses.length-1], "Port":info.port, "PIN":platform.config.HAPAccessories[info.name]});
        
    });  
    browser.on('serviceDown', function(info, flags) { 
        console.log("down "+info.name); 
        //
    }); 
    browser.on('error', function(error) {
        //console.error(error.stack);
    });
    browser.start();
  }.bind(this));

  function InitializeAccessory(HAPInformation) {
    PairingData={};
    PairingData.my_username = uuid.generate('hap-nodejs:client:'+HAPInformation.Name);
    PairingData.acc_mdnsname=HAPInformation.Name;
	  PairingData.acc_lastip=HAPInformation.IP;
	  PairingData.acc_lastport=HAPInformation.Port;
    PairingData.acc_pin=HAPInformation.PIN;

    var myPairing = new pairing(); 
    PairingData.PairProcess = myPairing;
    //throw an even instead of doing it here.
    myPairing.PairAccessory(PairingData);

  }
}

// Function invoked when homebridge tries to restore cached accessory
// Developer can configure accessory at here (like setup event handler)
// Update current value
HomeKitPlatform.prototype.configureAccessory = function(accessory) {
  this.log(accessory.displayName, "Configure Accessory");
  var platform = this;

  // set the accessory to reachable if plugin can currently process the accessory
  // otherwise set to false and update the reachability later by invoking 
  // accessory.updateReachability()
  accessory.reachable = false;

  accessory.on('identify', function(paired, callback) {
    platform.log(accessory.displayName, "Identify!!!");
    callback();
  });

  this.accessories.push(accessory);
}

//Handler will be invoked when user try to config your plugin
//Callback can be cached and invoke when nessary
HomeKitPlatform.prototype.configurationRequestHandler = function(context, request, callback) {
  this.log("Context: ", JSON.stringify(context));
  this.log("Request: ", JSON.stringify(request));

  // Check the request response
  if (request && request.response && request.response.inputs && request.response.inputs.name) {
    this.addAccessory(request.response.inputs.name);

    // Invoke callback with config will let homebridge save the new config into config.json
    // Callback = function(response, type, replace, config)
    // set "type" to platform if the plugin is trying to modify platforms section
    // set "replace" to true will let homebridge replace existing config in config.json
    // "config" is the data platform trying to save
    callback(null, "platform", true, {"platform":"HomeKitPlatform", "otherConfig":"SomeData"});
    return;
  }

  // - UI Type: Input
  // Can be used to request input from user
  // User response can be retrieved from request.response.inputs next time
  // when configurationRequestHandler being invoked

  var respDict = {
    "type": "Interface",
    "interface": "input",
    "title": "Add Accessory",
    "items": [
      {
        "id": "name",
        "title": "Name",
        "placeholder": "Fancy Light"
      }//, 
      // {
      //   "id": "pw",
      //   "title": "Password",
      //   "secure": true
      // }
    ]
  }

  // - UI Type: List
  // Can be used to ask user to select something from the list
  // User response can be retrieved from request.response.selections next time
  // when configurationRequestHandler being invoked

  // var respDict = {
  //   "type": "Interface",
  //   "interface": "list",
  //   "title": "Select Something",
  //   "allowMultipleSelection": true,
  //   "items": [
  //     "A","B","C"
  //   ]
  // }

  // - UI Type: Instruction
  // Can be used to ask user to do something (other than text input)
  // Hero image is base64 encoded image data. Not really sure the maximum length HomeKit allows.

  // var respDict = {
  //   "type": "Interface",
  //   "interface": "instruction",
  //   "title": "Almost There",
  //   "detail": "Please press the button on the bridge to finish the setup.",
  //   "heroImage": "base64 image data",
  //   "showActivityIndicator": true,
  // "showNextButton": true,
  // "buttonText": "Login in browser",
  // "actionURL": "https://google.com"
  // }

  // Plugin can set context to allow it track setup process
  context.ts = "Hello";

  //invoke callback to update setup UI
  callback(respDict);
}

// Sample function to show how developer can add accessory dynamically from outside event
HomeKitPlatform.prototype.addAccessory = function(accessoryName) {
  this.log("Add Accessory");
  var platform = this;
  var uuid;

  uuid = UUIDGen.generate(accessoryName);

  var newAccessory = new Accessory(accessoryName, uuid);
  newAccessory.on('identify', function(paired, callback) {
    platform.log(accessory.displayName, "Identify!!!");
    callback();
  });
  // Plugin can save context on accessory
  // To help restore accessory in configureAccessory()
  // newAccessory.context.something = "Something"

  newAccessory.addService(Service.Lightbulb, "Test Light")
  .getCharacteristic(Characteristic.On)
  .on('set', function(value, callback) {
    platform.log(accessory.displayName, "Light -> " + value);
    callback();
  });

  this.accessories.push(newAccessory);
  this.api.registerPlatformAccessories("homebridge-HomeKitPlatform", "HomeKitPlatform", [newAccessory]);
}

HomeKitPlatform.prototype.updateAccessoriesReachability = function() {
  this.log("Update Reachability");
  for (var index in this.accessories) {
    var accessory = this.accessories[index];
    accessory.updateReachability(false);
  }
}

// Sample function to show how developer can remove accessory dynamically from outside event
HomeKitPlatform.prototype.removeAccessory = function() {
  this.log("Remove Accessory");
  this.api.unregisterPlatformAccessories("homebridge-HomeKitPlatform", "HomeKitPlatform", this.accessories);

  this.accessories = [];
}
