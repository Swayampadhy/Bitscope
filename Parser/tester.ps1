<#
.SYNOPSIS
    RPC Packet Generator for Parser Testing
.DESCRIPTION
    Generates various types of benign and malicious RPC packets to test parser robustness.
    Supports both DCE/RPC connectionless and connection-oriented protocols.
.NOTES
    Author: Security Testing Tool
    Version: 1.0
    Requires: Administrator privileges for raw socket operations
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TargetIP = "127.0.0.1",
    
    [Parameter(Mandatory=$false)]
    [int]$TargetPort = 135,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "rpc_packets.log",
    
    [Parameter(Mandatory=$false)]
    [switch]$SendPackets = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateOnly = $true
)

# Import required assemblies for socket operations
Add-Type -AssemblyName System.Net.Sockets
Add-Type -AssemblyName System.Net

class RPCPacketGenerator {
    [string]$LogFile
    [string]$TargetIP
    [int]$TargetPort
    [System.Net.Sockets.Socket]$Socket
    
    # RPC packet types based on DCE/RPC specification
    static [hashtable]$PacketTypes = @{
        'REQUEST' = 0
        'RESPONSE' = 2
        'FAULT' = 3
        'BIND' = 11
        'BIND_ACK' = 12
        'BIND_NAK' = 13
        'ALTER_CONTEXT' = 14
        'ALTER_CONTEXT_RESP' = 15
        'SHUTDOWN' = 17
    }
    
    # RPC flags for fragmentation and authentication
    static [hashtable]$PacketFlags = @{
        'PFC_FIRST_FRAG' = 0x01
        'PFC_LAST_FRAG' = 0x02
        'PFC_PENDING_CANCEL' = 0x04
        'PFC_RESERVED_1' = 0x08
        'PFC_CONC_MPX' = 0x10
        'PFC_DID_NOT_EXECUTE' = 0x20
        'PFC_MAYBE' = 0x40
        'PFC_OBJECT_UUID' = 0x80
    }
    
    RPCPacketGenerator([string]$logFile, [string]$targetIP, [int]$targetPort) {
        $this.LogFile = $logFile
        $this.TargetIP = $targetIP
        $this.TargetPort = $targetPort
        $this.InitializeSocket()
    }
    
    [void] InitializeSocket() {
        try {
            $this.Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, 
                                                               [System.Net.Sockets.SocketType]::Stream, 
                                                               [System.Net.Sockets.ProtocolType]::Tcp)
            $this.LogMessage("Socket initialized successfully")
        }
        catch {
            $this.LogMessage("Failed to initialize socket: $_")
        }
    }
    
    [void] LogMessage([string]$message) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "$timestamp - $message"
        Write-Host $logEntry
        Add-Content -Path $this.LogFile -Value $logEntry
    }
    
    # Generate DCE/RPC Connection-Oriented Header (24 bytes)
    [byte[]] GenerateConnectionOrientedHeader([int]$packetType, [byte]$flags, [int]$fragLength, [int]$callId) {
        $header = New-Object byte[] 16
        
        # RPC Version (1 byte) - Version 5.0
        $header[0] = 0x05
        
        # Minor Version (1 byte)
        $header[1] = 0x00
        
        # Packet Type (1 byte)
        $header[2] = [byte]$packetType
        
        # Flags (1 byte)
        $header[3] = $flags
        
        # Data Representation (4 bytes) - Little Endian
        $header[4] = 0x10  # Character set
        $header[5] = 0x00  # Byte order
        $header[6] = 0x00  # Floating point
        $header[7] = 0x00  # Reserved
        
        # Fragment Length (2 bytes)
        [byte[]]$lengthBytes = [System.BitConverter]::GetBytes([uint16]$fragLength)
        $header[8] = $lengthBytes[0]
        $header[9] = $lengthBytes[1]
        
        # Authentication Length (2 bytes)
        $header[10] = 0x00
        $header[11] = 0x00
        
        # Call ID (4 bytes)
        [byte[]]$callIdBytes = [System.BitConverter]::GetBytes([uint32]$callId)
        $header[12] = $callIdBytes[0]
        $header[13] = $callIdBytes[1]
        $header[14] = $callIdBytes[2]
        $header[15] = $callIdBytes[3]
        
        return $header
    }
    
    # Generate DCE/RPC Connectionless Header (80 bytes)
    [byte[]] GenerateConnectionlessHeader([int]$packetType, [byte]$flags) {
        $header = New-Object byte[] 80
        
        # RPC Version (1 byte)
        $header[0] = 0x04
        
        # Packet Type (1 byte)
        $header[1] = [byte]$packetType
        
        # Flags (1 byte)
        $header[2] = $flags
        
        # Flags2 (1 byte)
        $header[3] = 0x00
        
        # Data Representation (3 bytes)
        $header[4] = 0x10  # Character set
        $header[5] = 0x00  # Byte order
        $header[6] = 0x00  # Floating point
        
        # Serial Hi (1 byte)
        $header[7] = 0x00
        
        # Object UUID (16 bytes) - All zeros for null UUID
        for ($i = 8; $i -lt 24; $i++) {
            $header[$i] = 0x00
        }
        
        # Interface UUID (16 bytes) - Sample interface UUID
        $interfaceUuid = [byte[]](0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef)
        for ($i = 0; $i -lt 16; $i++) {
            $header[24 + $i] = $interfaceUuid[$i]
        }
        
        # Activity UUID (16 bytes) - Random activity UUID
        for ($i = 40; $i -lt 56; $i++) {
            $header[$i] = Get-Random -Minimum 0 -Maximum 256
        }
        
        # Server Boot Time (4 bytes)
        $bootTime = [System.BitConverter]::GetBytes([uint32](Get-Date).Ticks)
        for ($i = 0; $i -lt 4; $i++) {
            $header[56 + $i] = $bootTime[$i]
        }
        
        # Interface Version (4 bytes)
        $header[60] = 0x01
        $header[61] = 0x00
        $header[62] = 0x00
        $header[63] = 0x00
        
        # Sequence Number (4 bytes)
        $seqNum = [System.BitConverter]::GetBytes([uint32]1)
        for ($i = 0; $i -lt 4; $i++) {
            $header[64 + $i] = $seqNum[$i]
        }
        
        # Operation Number (2 bytes)
        $header[68] = 0x01
        $header[69] = 0x00
        
        # Interface Hint (2 bytes)
        $header[70] = 0xff
        $header[71] = 0xff
        
        # Activity Hint (2 bytes)
        $header[72] = 0xff
        $header[73] = 0xff
        
        # Length of Packet Body (2 bytes)
        $header[74] = 0x00
        $header[75] = 0x00
        
        # Fragment Number (2 bytes)
        $header[76] = 0x00
        $header[77] = 0x00
        
        # Authentication Protocol (1 byte)
        $header[78] = 0x00
        
        # Serial Low (1 byte)
        $header[79] = 0x00
        
        return $header
    }
    
    # Generate benign RPC packets
    [hashtable[]] GenerateBenignPackets() {
        $packets = @()
        
        # 1. Valid BIND request
        $bindHeader = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['BIND'], 
                                                            [RPCPacketGenerator]::PacketFlags['PFC_FIRST_FRAG'] -bor [RPCPacketGenerator]::PacketFlags['PFC_LAST_FRAG'], 
                                                            72, 1)
        $bindData = New-Object byte[] 56  # Minimal bind data
        $bindPacket = $bindHeader + $bindData
        
        $packets += @{
            'Name' = 'Valid BIND Request'
            'Type' = 'Benign'
            'Data' = $bindPacket
            'Description' = 'Standard RPC BIND request with proper header structure'
        }
        
        # 2. Valid REQUEST packet
        $requestHeader = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 
                                                               [RPCPacketGenerator]::PacketFlags['PFC_FIRST_FRAG'] -bor [RPCPacketGenerator]::PacketFlags['PFC_LAST_FRAG'], 
                                                               32, 2)
        $requestData = New-Object byte[] 16  # Minimal request data
        $requestPacket = $requestHeader + $requestData
        
        $packets += @{
            'Name' = 'Valid REQUEST'
            'Type' = 'Benign'
            'Data' = $requestPacket
            'Description' = 'Standard RPC REQUEST with proper formatting'
        }
        
        # 3. Valid connectionless packet
        $clHeader = $this.GenerateConnectionlessHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 0x03)
        $packets += @{
            'Name' = 'Valid Connectionless REQUEST'
            'Type' = 'Benign'
            'Data' = $clHeader
            'Description' = 'Standard connectionless RPC packet'
        }
        
        return $packets
    }
    
    # Generate malicious RPC packets for testing
    [hashtable[]] GenerateMaliciousPackets() {
        $packets = @()
        
        # 1. Buffer Overflow - Oversized fragment length
        $malformedHeader = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 
                                                                 [RPCPacketGenerator]::PacketFlags['PFC_FIRST_FRAG'], 
                                                                 0xFFFF, 3)  # Maximum fragment length
        $packets += @{
            'Name' = 'Buffer Overflow - Oversized Fragment'
            'Type' = 'Malicious'
            'Data' = $malformedHeader
            'Description' = 'Packet with maximum fragment length to test buffer overflow handling'
        }
        
        # 2. Integer Overflow - Negative fragment length
        $negativeHeader = New-Object byte[] 16
        $validHeader = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['BIND'], 0x03, 100, 4)
        $validHeader.CopyTo($negativeHeader, 0)
        # Manually set fragment length to negative value
        $negativeHeader[8] = 0xFF
        $negativeHeader[9] = 0xFF
        
        $packets += @{
            'Name' = 'Integer Overflow - Negative Length'
            'Type' = 'Malicious'
            'Data' = $negativeHeader
            'Description' = 'Packet with negative fragment length to test integer overflow'
        }
        
        # 3. Fragmentation Attack - Missing last fragment
        $fragHeader = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 
                                                            [RPCPacketGenerator]::PacketFlags['PFC_FIRST_FRAG'],  # Missing PFC_LAST_FRAG
                                                            50, 5)
        $fragData = New-Object byte[] 34
        for ($i = 0; $i -lt $fragData.Length; $i++) {
            $fragData[$i] = Get-Random -Minimum 0 -Maximum 256
        }
        
        $packets += @{
            'Name' = 'Fragmentation Attack - Incomplete Fragment'
            'Type' = 'Malicious'
            'Data' = $fragHeader + $fragData
            'Description' = 'Fragment marked as first but never completed'
        }
        
        # 4. Protocol Violation - Invalid packet type
        $invalidTypeHeader = $this.GenerateConnectionOrientedHeader(0xFF,  # Invalid packet type
                                                                   0x03, 30, 6)
        
        $packets += @{
            'Name' = 'Protocol Violation - Invalid Type'
            'Type' = 'Malicious'
            'Data' = $invalidTypeHeader
            'Description' = 'Packet with invalid/unknown packet type'
        }
        
        # 5. Authentication Bypass - Malformed auth length
        $authBypassHeader = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['ALTER_CONTEXT'], 
                                                                  0x03, 24, 7)
        # Manually corrupt authentication length field
        $authBypassHeader[10] = 0xFF
        $authBypassHeader[11] = 0xFF
        
        $packets += @{
            'Name' = 'Authentication Bypass - Malformed Auth'
            'Type' = 'Malicious'
            'Data' = $authBypassHeader
            'Description' = 'Packet with corrupted authentication length'
        }
        
        # 6. Memory Corruption - Zero-length packet with data
        $zeroLengthHeader = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['RESPONSE'], 
                                                                  0x03, 0, 8)  # Zero length
        $unexpectedData = New-Object byte[] 100  # But has data anyway
        for ($i = 0; $i -lt $unexpectedData.Length; $i++) {
            $unexpectedData[$i] = 0x41  # 'A' characters
        }
        
        $packets += @{
            'Name' = 'Memory Corruption - Zero Length with Data'
            'Type' = 'Malicious'
            'Data' = $zeroLengthHeader + $unexpectedData
            'Description' = 'Zero-length packet header with unexpected data payload'
        }
        
        # 7. Connectionless Packet Size Mismatch
        $clMalformed = $this.GenerateConnectionlessHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 0xFF)
        # Corrupt the length field in connectionless header
        $clMalformed[74] = 0xFF
        $clMalformed[75] = 0xFF
        
        $packets += @{
            'Name' = 'Connectionless Size Mismatch'
            'Type' = 'Malicious'
            'Data' = $clMalformed
            'Description' = 'Connectionless packet with corrupted length field'
        }
        
        # 8. Malformed UUID Attack
        $uuidAttackHeader = $this.GenerateConnectionlessHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 0x03)
        # Corrupt interface UUID with invalid values
        for ($i = 24; $i -lt 40; $i++) {
            $uuidAttackHeader[$i] = 0xFF
        }
        
        $packets += @{
            'Name' = 'Malformed UUID Attack'
            'Type' = 'Malicious'
            'Data' = $uuidAttackHeader
            'Description' = 'Packet with malformed interface UUID'
        }
        
        # 9. Call ID Overflow
        $callIdOverflow = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 
                                                                0x03, 20, 0xFFFFFFFF)  # Maximum call ID
        
        $packets += @{
            'Name' = 'Call ID Overflow'
            'Type' = 'Malicious'
            'Data' = $callIdOverflow
            'Description' = 'Packet with maximum possible call ID value'
        }
        
        # 10. Rapid Fragment Attack
        $rapidFrags = @()
        for ($i = 0; $i -lt 10; $i++) {
            $fragFlag = if ($i -eq 0) { [RPCPacketGenerator]::PacketFlags['PFC_FIRST_FRAG'] } 
                       elseif ($i -eq 9) { [RPCPacketGenerator]::PacketFlags['PFC_LAST_FRAG'] } 
                       else { 0x00 }
            
            $rapidFrag = $this.GenerateConnectionOrientedHeader([RPCPacketGenerator]::PacketTypes['REQUEST'], 
                                                              $fragFlag, 20, 10)
            $rapidFrags += $rapidFrag
        }
        
        $packets += @{
            'Name' = 'Rapid Fragment Attack'
            'Type' = 'Malicious'
            'Data' = $rapidFrags
            'Description' = 'Series of rapid fragments to test reassembly logic'
        }
        
        return $packets
    }
    
    [void] SendPacket([byte[]]$packetData) {
        if ($this.Socket -eq $null) {
            $this.LogMessage("Socket not initialized")
            return
        }
        
        try {
            $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($this.TargetIP), $this.TargetPort)
            $this.Socket.Connect($endpoint)
            $bytesSent = $this.Socket.Send($packetData)
            $this.LogMessage("Sent $bytesSent bytes to $($this.TargetIP):$($this.TargetPort)")
            $this.Socket.Disconnect($false)
        }
        catch {
            $this.LogMessage("Failed to send packet: $_")
        }
    }
    
    [void] GenerateAndTestPackets([bool]$sendPackets) {
        $this.LogMessage("Starting RPC packet generation and testing...")
        
        # Generate benign packets
        $benignPackets = $this.GenerateBenignPackets()
        $this.LogMessage("Generated $($benignPackets.Count) benign packets")
        
        # Generate malicious packets
        $maliciousPackets = $this.GenerateMaliciousPackets()
        $this.LogMessage("Generated $($maliciousPackets.Count) malicious packets")
        
        # Process all packets
        $allPackets = $benignPackets + $maliciousPackets
        
        foreach ($packet in $allPackets) {
            $this.LogMessage("Processing: $($packet.Name) [$($packet.Type)]")
            $this.LogMessage("Description: $($packet.Description)")
            
            if ($packet.Data -is [array] -and $packet.Data[0] -is [byte[]]) {
                # Handle array of byte arrays (like rapid fragments)
                foreach ($fragment in $packet.Data) {
                    $hexData = ($fragment | ForEach-Object { "{0:X2}" -f $_ }) -join " "
                    $this.LogMessage("Packet Data (Length: $($fragment.Length)): $hexData")
                    
                    if ($sendPackets) {
                        $this.SendPacket($fragment)
                        Start-Sleep -Milliseconds 100  # Small delay between fragments
                    }
                }
            }
            else {
                # Handle single byte array
                $hexData = ($packet.Data | ForEach-Object { "{0:X2}" -f $_ }) -join " "
                $this.LogMessage("Packet Data (Length: $($packet.Data.Length)): $hexData")
                
                if ($sendPackets) {
                    $this.SendPacket($packet.Data)
                    Start-Sleep -Milliseconds 500  # Delay between packets
                }
            }
            
            $this.LogMessage("---")
        }
        
        $this.LogMessage("Packet generation and testing completed")
    }
    
    [void] Cleanup() {
        if ($this.Socket -ne $null) {
            $this.Socket.Close()
            $this.Socket = $null
        }
    }
}

# Main execution
try {
    Write-Host "RPC Packet Generator for Parser Testing" -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor Green
    
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "This script may require Administrator privileges for raw socket operations"
    }
    
    # Initialize packet generator
    $generator = [RPCPacketGenerator]::new($OutputFile, $TargetIP, $TargetPort)
    
    # Generate and optionally send packets
    $generator.GenerateAndTestPackets($SendPackets)
    
    Write-Host "`nPacket generation completed. Check '$OutputFile' for detailed logs." -ForegroundColor Green
    
    if ($SendPackets) {
        Write-Host "Packets were sent to $TargetIP`:$TargetPort" -ForegroundColor Yellow
    } else {
        Write-Host "Packets were only generated (not sent). Use -SendPackets to transmit them." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Script execution failed: $_"
}
finally {
    if ($generator -ne $null) {
        $generator.Cleanup()
    }
}
