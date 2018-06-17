"""Parse MinXSS packet"""
__author__ = "James Paul Mason"
__contact__ = "jmason86@gmail.com"

import os
import logging
import pdb, binascii
import math
from numpy import int8, uint8, int16, uint16, int32, uint32 

class Minxss_Parser():
    def __init__(self, inspirePacket, log):
        self.log = log # debug log

    # Purpose:
    #   Top level wrapper function to take serial data and return parsed and interpretted telemetry as a dictionary
    # Input:
    #   inspirePacket [bytearray]: The direct output of the python serial line (connect_serial_decode_kiss.read()), or simulated data in that format
    # Output:
    #   selectedTelemetryDictionary [dictionary]: The telemetry with key/value pairs
    #
    def parsePacket(self, inspirePacket):
        # Find the sync bytes (0x08, 0x19), reframe the packet to start after sync
        syncOffset = self.findSyncStartIndex(inspirePacket)
        if syncOffset == -1:
            self.log.error("No start sync bytes found in minxss_parser, exiting.")
            return -1
        else:
            inspirePacket = inspirePacket[syncOffset:len(inspirePacket)]
        
        # Prepare a dictionary for storage of telemetry points
        selectedTelemetryDictionary = {}
        
        # Get the telemetry points
        # Note: Second index in range of inspirePacket must be +1 what you'd normally expect because python is wonky
        # For example, to grab bytes at indices 3 and 4, you don't do inspirePacket[3:4], you have to do inspirePacket[3:5]
        # C&DH
        selectedTelemetryDictionary['Time Stamp'] = self.decodeTimeStamp(inspirePacket[0:5])
        selectedTelemetryDictionary['Commands Received'] = self.decodeCommandReceivedCount(inspirePacket[5:5 + 4])
        selectedTelemetryDictionary['Last Command Received'] = self.decodeLastCommandReceived(inspirePacket[9:9 + 2])
        selectedTelemetryDictionary['Temperature'] = self.decodeTemperature(inspirePacket[11:13])
        selectedTelemetryDictionary['C&DH Primary Data'] = self.decodeCDHPrimaryData(
            inspirePacket[13:13 + 1])  # Contains Mode, Eclipse and BT_Enable
        selectedTelemetryDictionary['Rejected CIP Packets'] = self.decodeRejectedCIPPackets(inspirePacket[14:14 + 4])
        selectedTelemetryDictionary['Last Downlinked HK Sector'] = self.decodeLastDownlinkedHKSector(
            inspirePacket[18:18 + 4])
        selectedTelemetryDictionary['Last downlinked Science Sector'] = self.LastdownlinkedScienceSector(
            inspirePacket[22:22 + 4])
        selectedTelemetryDictionary['Last downlinked ADCS Sector'] = self.LastdownlinkedADCSSector(
            inspirePacket[26:26 + 4])

        # EPS
        selectedTelemetryDictionary['Battery Voltage'] = self.BatteryVoltage(inspirePacket[29:31])
        selectedTelemetryDictionary['Battery Current'] = self.decodeBatteryCurrent(inspirePacket[31:33])
        selectedTelemetryDictionary['Battery SOC'] = self.decodeBatterySOC(inspirePacket[33:35])
        selectedTelemetryDictionary['Battery Temperature'] = self.decodeBatteryTemperature(inspirePacket[35:43])
        selectedTelemetryDictionary['Solar Panel Voltage'] = self.decodeSolarPanelVoltage(inspirePacket[43:49])
        selectedTelemetryDictionary['Solar Panel Current'] = self.decodeSolarPanelCurrent(inspirePacket[49:54])

        # Interface
        selectedTelemetryDictionary['Interface Board Temperature'] = self.decodeInterfaceBoardTemperature(
            inspirePacket[54:56])

        # EPS
        selectedTelemetryDictionary['EPS Board Temperature'] = self.decodeEPSBoardTemperature(
            inspirePacket[56:58])  # [deg C]
        selectedTelemetryDictionary['CIP Voltage'] = self.decodeCIPVoltage(inspirePacket[58:60])  # [V]
        selectedTelemetryDictionary['CIP Current'] = self.decodeCIPCurrent(inspirePacket[60:62])  # [mA]
        selectedTelemetryDictionary['ADCS Voltage'] = self.decodeADCSVoltage(
            inspirePacket[62:64])  # [V]
        selectedTelemetryDictionary['ADCS Current'] = self.decodeADCSCurrent(
            inspirePacket[64:66])  # [mA]
        selectedTelemetryDictionary['S-Band Voltage'] = self.decodeSBandVoltage(
            inspirePacket[66:66 + 2])  # [V]
        selectedTelemetryDictionary['S-Band Current'] = self.decodeSBandCurrent(
            inspirePacket[68:68 + 2])  # [mA]
        selectedTelemetryDictionary['UHF Voltage'] = self.decodeUHFVoltage(
            inspirePacket[70:70 + 2])  # [mA]
        selectedTelemetryDictionary['UHF Current'] = self.decodeUHFCurrent(
            inspirePacket[72:72 + 2])  # [mA]
        selectedTelemetryDictionary['C&DH Voltage'] = self.decodeCDHVoltage(
            inspirePacket[74:74 + 2])  # [V]
        selectedTelemetryDictionary['C&DH Current'] = self.decodeCDHCurrent(
            inspirePacket[76:76 + 2])  # [V]
        selectedTelemetryDictionary['GPS 3.3 Voltage'] = self.decodeGPS3Voltage(
            inspirePacket[78:78 + 2])  # [V]
        selectedTelemetryDictionary['GPS 3.3 Current'] = self.decodeGPS3Current(
            inspirePacket[80:80 + 2])  # [V]
        selectedTelemetryDictionary['GPS 12 Voltage'] = self.decodeGPS12Voltage(
            inspirePacket[82:82 + 6])  # [V]
        selectedTelemetryDictionary['GPS 12 Current'] = self.decodeGPS12Current(
            inspirePacket[88:88 + 6])  # [V]
        selectedTelemetryDictionary['Battery Heater Current'] = self.decodeBatteryHeaterCurrent(
            inspirePacket[94:94 + 2])  # [V]

        # CIP
        selectedTelemetryDictionary['General Information'] = self.decodeGeneralInfo(
            inspirePacket[96:96 + 4])  # [V]
        selectedTelemetryDictionary['CIP Temperature'] = self.decodeCIPTemperature(
            inspirePacket[100:100 + 6])  # [V]

        # UHF
        selectedTelemetryDictionary['System Check Temperature'] = self.decodeSystemChecksTemp(
            inspirePacket[106:106 + 2])  # [V]
        selectedTelemetryDictionary['System Check Current Channel'] = self.decodeSystemCheckCurrent(
            inspirePacket[108:108 + 1])  # [V]
        selectedTelemetryDictionary['Shell Temperature'] = self.decodeShellTemp(
            inspirePacket[109:109 + 2])  # [V]
        selectedTelemetryDictionary['Check Sum Counter'] = self.decodeCheckSumCounter(
            inspirePacket[111:111 + 2])  # [V]
        selectedTelemetryDictionary['Configuration Status'] = self.decodeConfigurationStatus(
            inspirePacket[113:113 + 1])  # [V]

        # SBand
        selectedTelemetryDictionary['SBandByte'] = self.decodeSBandByte(
            inspirePacket[114:114 + 1])  # Includes Scrambler Status, PA Gain and Status Register

        # ADCS
        selectedTelemetryDictionary['Command Status'] = self.decodeCommandStatus(
            inspirePacket[115:115 + 1])  # [V]
        selectedTelemetryDictionary['Command Reject Count'] = self.decodeCommandRejectCount(
            inspirePacket[116:116 + 1])  # [V]
        selectedTelemetryDictionary['Command Accept Count'] = self.decodeCommandAcceptCount(
            inspirePacket[117:117 + 1])  # [V]
        selectedTelemetryDictionary['Time Valid'] = self.decodeTimeValid(
            inspirePacket[118:118 + 1])  # [V]
        selectedTelemetryDictionary['Time Now'] = self.decodeTimeNow(
            inspirePacket[119:119 + 4])  # [V]
        selectedTelemetryDictionary['Refs Valid'] = self.decodeRefsValid(
            inspirePacket[123:123 + 1])
        selectedTelemetryDictionary['Attitude Valid'] = self.decodeAttitudeValid(
            inspirePacket[123:123 + 1])  # [V]
        selectedTelemetryDictionary['ADCS Mode'] = self.decodeADCSMode(
            inspirePacket[124:124 + 1])  # [V]
        selectedTelemetryDictionary['Recommend Sun Point'] = self.decodeRecommendSunPoint(
            inspirePacket[125:125 + 1])  # [V]
        selectedTelemetryDictionary['Sun Point State'] = self.decodeSunPointState(
            inspirePacket[126:126 + 1])  # [V]
        selectedTelemetryDictionary['Star Tracker Temperature'] = self.decodeStarTrackerTemperature(
            inspirePacket[127:127 + 1])  # [V]
        selectedTelemetryDictionary['Wheel Temperatures'] = self.decodeWheelTemperatures(
            inspirePacket[128:128 + 6])  # [V]
        selectedTelemetryDictionary['Digital Bus Voltage'] = self.decodeDigitalBusVoltage(
            inspirePacket[134:134 + 2])  # [V]
        selectedTelemetryDictionary['Sun Vector'] = self.decodeSunVector(
            inspirePacket[136:136 + 6])  # [V]
        selectedTelemetryDictionary['Wheel Est Drag'] = self.decodeWheelEstDrag(
            inspirePacket[142:142 + 6])  # [V]
        selectedTelemetryDictionary['Wheel Measured Speed'] = self.decodeWheelMeasuredSpeed(
            inspirePacket[148:148 + 6])  # [V]
        selectedTelemetryDictionary['Body Frame Rate'] = self.decodeBodyFrameRate(
            inspirePacket[154:154 + 12])  # [V]
        
        self.log.info("From MinXSS parser:")
        self.log.info(selectedTelemetryDictionary)
        return selectedTelemetryDictionary

    # Purpose:
    #   Find the start of the MinXSS packet and return the index within minxssSerialData
    # Input:
    #   minxssSerialData [bytearray]: The direct output of the python serial line (connect_serial_decode_kiss.read()), or simulated data in that format
    # Output:
    #   packetStartIndex [int]: The index within minxssSerialData where the start sync bytes were found. -1 if not found.
    #
    def findSyncStartIndex(self, minxssSerialData):
        syncBytes = bytearray([0x08, 0x19]) # Other Cubesats: Change these start sync bytes to whatever you are using to define the start of your packet
        packetStartIndex = bytearray(minxssSerialData).find(syncBytes)
        return packetStartIndex
    
    # Purpose:
    #   Find the end of the MinXSS packet and return the index within minxssSerialData
    # Input:
    #   minxssSerialData [bytearray]: The direct output of the python serial line (connect_serial_decode_kiss.read()), or simulated data in that format
    # Output:
    #   packetStopIndex [int]: The index within minxssSerialData where the end sync bytes were found. -1 if not found.
    #
    def findSyncStopIndex(self, minxssSerialData):
        syncBytes = bytearray([0xa5, 0xa5]) # Other CubeSats: Change these stop sync bytes to whatever you are using to define the end of your packet
        packetStopIndex = bytearray(minxssSerialData).find(syncBytes)
        return packetStopIndex
    
    # Purpose:
    #   Combine several bytes corresponding to a single telemetry point to a single integer
    # Input:
    #   bytearrayTemp [bytearray]: The bytes corresponding to the telemetry to decode.
    #                              Can accept any number of bytes but do not expect more than 4
    # Flags:
    #   returnUnsignedInt: Set this to 1 or True to return an unsigned integer instead of the default signed integer
    # Output:
    #   telemetryPointRaw [int]: The single integer for the telemetry point to be converted to human-readable by the appropriate function
    #
    def decodeBytes(self, bytearrayTemp, returnUnsignedInt = 0):
        if len(bytearrayTemp) == 1:
            return bytearrayTemp
        elif len(bytearrayTemp) == 2:
            if returnUnsignedInt:
                return uint16((int8(bytearrayTemp[1]) << 8) | uint8(bytearrayTemp[0]))
            else:
                return int16((uint8(bytearrayTemp[1]) << 8) | uint8(bytearrayTemp[0]))
        elif len(bytearrayTemp) == 4:
            if returnUnsignedInt:
                return uint32((uint8(bytearrayTemp[3]) << 24) | (uint8(bytearrayTemp[2] << 16)) |
                                (uint8(bytearrayTemp[1] << 8)) | (uint8(bytearrayTemp[0] << 0)))
            else:
                return int32((uint8(bytearrayTemp[3]) << 24) | (uint8(bytearrayTemp[2] << 16)) |
                                (uint8(bytearrayTemp[1] << 8)) | (uint8(bytearrayTemp[0] << 0)))
        else:
            self.log.debug("More bytes than expected")

    # Purpose:
    #   Converts the Voltage across thermistor , which is recieved from telemetry , to Temperature.
    # Input:
    #   bytearrayTemp [bytearray]: The bytes corresponding to the telemetry to decode.
    #                              Can accept 2 bytes
    # Output:
    #   Temperature in Celsius

    def TempCalc(self, bytearrayTemp):
        Tinv = 1 / 298
        B = 3430  # Confirm Value
        Voltage_thermistor = bytearrayTemp[0] + bytearrayTemp[1]
        Resistance_thermistor = ((Voltage_thermistor / (3.3 - Voltage_thermistor)) * 23 * 1000)
        R = Resistance_thermistor / 10000
        Temperature = (1/(((Tinv) + ((math.log(R) / B)))))  # In Kelvin
        return (Temperature-273)  # In Celsius





    ##
    # The following functions all have the same purpose: to convert raw bytes to human-readable output.
    # Only the units will be commented on. The function and variable names are explicit and verbose for clarity.
    ##
    
    # Purpose:
    #   Convert raw telemetry to human-readable number in human-readable units
    # Input:
    #   bytearrayTemp [bytearray]: The bytes corresponding to the telemetry to decode.
    #                              Can accept any number of bytes but do not expect more than 4
    # Output:
    #   telemetryPoint [int, float, string, as appropriate]: The telemetry point in human-readable form and units
    #
    
    def decodeTimeStamp(self, bytearrayTemp):
        return

    def decodeCommandReceivedCount(self, bytearrayTemp):
        return

    def decodeLastCommandReceived(self, bytearrayTemp):
        return

    def decodeTemperature(self, bytearrayTemp):
        return (self.TempCalc(bytearrayTemp))

    def decodeCDHPrimaryData(self, bytearrayTemp):
        return

    def decodeRejectedCIPPackets(self, bytearrayTemp):
        return

    def decodeLastDownlinkedHKSector(self, bytearrayTemp):
        return

    def LastdownlinkedScienceSector(self, bytearrayTemp):
        return

    def LastdownlinkedADCSSector(self, bytearrayTemp):
        return

    def BatteryVoltage(self, bytearrayTemp):
        #Calculatind Battery Voltage , refer INA3221 Datasheet Pg 27
        temp_hexdata = bytearrayTemp[0]+bytearrayTemp[1]
        scale = 16
        num_of_bits = 16
        bin(int(temp_hexdata, scale))[2:].zfill(num_of_bits)

        return self.decodeBytes(bytearrayTemp)

    def decodeBatteryCurrent(self, bytearrayTemp):
        return

    def decodeBatterySOC(self, bytearrayTemp):
        return

    def decodeBatteryTemperature(self, bytearrayTemp):
        return (self.TempCalc(bytearrayTemp))

    def decodeSolarPanelVoltage(self, bytearrayTemp):
        return

    def decodeSolarPanelCurrent(self, bytearrayTemp):
        return

    def decodeInterfaceBoardTemperature(self, bytearrayTemp):
        return (self.TempCalc(bytearrayTemp))

    def decodeEPSBoardTemperature(self, bytearrayTemp):
        return (self.TempCalc(bytearrayTemp))

    def decodeCIPVoltage(self, bytearrayTemp):
        return 1

    def decodeCIPCurrent(self, bytearrayTemp):
        return 1

    def decodeADCSVoltage(self, bytearrayTemp):
        return 1

    def decodeADCSCurrent(self, bytearrayTemp):
        return 1

    def decodeSBandVoltage(self, bytearrayTemp):
        return 1

    def decodeSBandCurrent(self, bytearrayTemp):
        return 1

    def decodeUHFVoltage(self, bytearrayTemp):
        return 1

    def decodeUHFCurrent(self, bytearrayTemp):
        return 1

    def decodeCDHVoltage(self, bytearrayTemp):
        return 1

    def decodeCDHCurrent(self, bytearrayTemp):
        return 1

    def decodeGPS3Voltage(self, bytearrayTemp):
        return 1

    def decodeGPS3Current(self, bytearrayTemp):
        return 1

    def decodeGPS12Voltage(self, bytearrayTemp):
        return 1

    def decodeGPS12Current(self, bytearrayTemp):
        return 1

    def decodeBatteryHeaterCurrent(self, bytearrayTemp):
        return 1

    def decodeGeneralInfo(self, bytearrayTemp):
        return 1

    def decodeCIPTemperature(self, bytearrayTemp):
        return 1

    def decodeSystemChecksTemp(self, bytearrayTemp):
        return 1

    def decodeSystemCheckCurrent(self, bytearrayTemp):
        return 1

    def decodeShellTemp(self, bytearrayTemp):
        return 1

    def decodeCheckSumCounter(self, bytearrayTemp):
        return 1

    def decodeConfigurationStatus(self, bytearrayTemp):
        return 1

    def decodeSBandByte(self, bytearrayTemp):
        return 1

    def decodeCommandStatus(self, bytearrayTemp):
        return 1

    def decodeCommandRejectCount(self, bytearrayTemp):
        return 1

    def decodeCommandAcceptCount(self, bytearrayTemp):
        return 1

    def decodeTimeValid(self, bytearrayTemp):
        return 1

    def decodeTimeNow(self, bytearrayTemp):
        return 1

    def decodeAttitudeValid(self, bytearrayTemp):
        return 1

    def decodeRefsValid(self, bytearrayTemp):
        return 1

    def decodeADCSMode(self, bytearrayTemp):
        return 1

    def decodeRecommendSunPoint(self, bytearrayTemp):
        return 1

    def decodeSunPointState(self, bytearrayTemp):
        return 1

    def decodeStarTrackerTemperature(self, bytearrayTemp):
        return 1

    def decodeWheelTemperatures(self, bytearrayTemp):
        return 1

    def decodeDigitalBusVoltage(self, bytearrayTemp):
        return 1

    def decodeSunVector(self, bytearrayTemp):
        return 1

    def decodeWheelEstDrag(self, bytearrayTemp):
        return 1

    def decodeWheelMeasuredSpeed(self, bytearrayTemp):
        return 1

    def decodeBodyFrameRate(self, bytearrayTemp):
        return 1


    ##
    # End byte->human-readable conversion functions
    ##
    
    # Purpose:
    #   Test parsing a packet
    # Input:
    #   inspirePacket [bytearray]: The direct output of the python serial line (connect_serial_decode_kiss.read()), or simulated data in that format
    # Output:
    #   ... not sure yet
    #
    def testParsePacket(self, inspirePacket, log):
        log.info("Testing MinXSS packet parse")
        selectedTelemetryDictionary = self.parsePacket(inspirePacket)
        print (selectedTelemetryDictionary)
        log.info(selectedTelemetryDictionary)

# Purpose:
#   If called directly from Unix, just do a test
#
if __name__ == '__main__':
    # Create a typical telemetry packet as received by the serial line
    exampleData = bytearray([0xc0, 0x00, 0x9a, 0x92, 0x00, 0xb0, 0xa6, 0x64, 0x60, 0x86,
                             0xa2, 0x40, 0x40, 0x40, 0x40, 0xe1, 0x03, 0xf0, 0x08, 0x19,
                             0xc1, 0x6f, 0x00, 0xf7, 0xf1, 0x34, 0xd6, 0x45, 0x47, 0x02,
                             0x0a, 0x86, 0x4b, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x2e, 0x74,
                             0x01, 0x03, 0x30, 0x03, 0x00, 0x03, 0x79, 0x00, 0x00, 0x01,
                             0xfa, 0xc7, 0x10, 0x01, 0x03, 0x00, 0x00, 0x01, 0x5a, 0x80,
                             0x04, 0x01, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0x21,
                             0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                             0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x5f, 0x00,
                             0x47, 0x13, 0x00, 0x00, 0x0a, 0x80, 0xf6, 0x01, 0xe2, 0x03,
                             0xd3, 0x0b, 0x06, 0x08, 0x90, 0x18, 0x05, 0x04, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                             0x00, 0x00, 0x8e, 0x01, 0x13, 0x00, 0x6d, 0x00, 0x00, 0x64,
                             0x88, 0x01, 0x00, 0x00, 0xac, 0x25, 0x01, 0x00, 0x07, 0x0b,
                             0x20, 0x17, 0x40, 0x15, 0x90, 0x15, 0x80, 0x17, 0x40, 0x18,
                             0xe0, 0xce, 0x58, 0x61, 0x08, 0x00, 0x78, 0x07, 0x08, 0x00,
                             0x80, 0x06, 0x08, 0x00, 0x30, 0x06, 0x18, 0x00, 0x50, 0x20,
                             0x30, 0x01, 0x90, 0x0d, 0x18, 0x00, 0x78, 0x13, 0x4d, 0x05,
                             0x44, 0x05, 0x51, 0x05, 0x09, 0x08, 0x14, 0x00, 0x9e, 0x05,
                             0x6c, 0x00, 0xa0, 0x05, 0xf3, 0x01, 0x5c, 0x00, 0x4f, 0x02,
                             0x52, 0x02, 0x53, 0x01, 0x53, 0x01, 0x33, 0x01, 0x00, 0x00,
                             0x08, 0x01, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0xcd, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0xc7, 0x2f, 0x20, 0x12, 0xd8, 0x00, 0x00, 0x00,
                             0x05, 0x07, 0x02, 0x00, 0x00, 0x00, 0x27, 0x06, 0x00, 0x00,
                             0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff,
                             0xfd, 0xff, 0x07, 0x00, 0x07, 0x49, 0x00, 0x00, 0xe5, 0xf9,
                             0xa5, 0xa5, 0xc0])
