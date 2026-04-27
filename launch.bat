@echo off
REM ================================================================
REM  Anon-Sec-Net v2 -- Full System Launcher (15 processes)
REM
REM  Client paths:
REM    Sending:   Client -> MN1(9004) -> MN2(9005) -> MN3(9006) -> SvcGW
REM    Receiving: SvcGW  -> MNa(9007) -> MNb(9008) -> MNc(9009) -> Client
REM
REM  Sender paths:
REM    Sending:   Sender -> MNi(9030) -> MNii(9031) -> MNiii(9032) -> SvcGW
REM    Receiving: SvcGW  -> MNx(9033) -> MNy(9034)  -> MNz(9035)  -> Sender
REM
REM  SvcGW(9010) -> Cache(9012)
REM
REM  Start order:
REM    1. All 12 mix nodes  (write pubkeys)
REM    2. Cache + SvcGW     (SvcGW participates in ECDHE)
REM    3. Wait 4 seconds
REM    4. Sender            (builds path MNi->MNii->MNiii->SvcGW)
REM    5. Wait 3 seconds
REM    6. Client            (builds both paths, starts listening)
REM ================================================================

echo [Launch] Creating pubkey directory...
mkdir C:\Temp\ansn 2>nul

echo [Launch] Starting Client sending path mix nodes...
start "MN1  :9004" mix_node.exe 9004
start "MN2  :9005" mix_node.exe 9005
start "MN3  :9006" mix_node.exe 9006

echo [Launch] Starting Client receiving path mix nodes...
start "MNa  :9007" mix_node.exe 9007
start "MNb  :9008" mix_node.exe 9008
start "MNc  :9009" mix_node.exe 9009

echo [Launch] Starting Sender sending path mix nodes...
start "MNi  :9030" mix_node.exe 9030
start "MNii :9031" mix_node.exe 9031
start "MNiii:9032" mix_node.exe 9032

echo [Launch] Starting Sender receiving path mix nodes...
start "MNx  :9033" mix_node.exe 9033
start "MNy  :9034" mix_node.exe 9034
start "MNz  :9035" mix_node.exe 9035

echo [Launch] Starting Cache Server and Service Gateway...
start "Cache Server :9012" cache_server.exe
start "Service GW   :9010" service_gateway.exe

echo [Launch] Waiting 4 seconds for all nodes to be ready...
timeout /t 4 /nobreak >nul

echo [Launch] Starting Anonymous Sender...
start "Sender :9015" sender.exe

echo [Launch] Waiting 3 seconds for Sender path construction...
timeout /t 3 /nobreak >nul

echo [Launch] Starting Client...
start "Client :9001" client.exe

echo.
echo [Launch] All 15 processes started.
echo.
echo  HOW TO USE:
echo    1. Sender window:  PUT homepage Hello from the anonymous service
echo    2. Client window:  GET homepage
echo.
echo  WHAT TO WATCH:
echo    MN1/MNi windows:  "extend: session ready" during path build
echo    MN1-3 windows:    "data: peeled OK" on GET/PUT requests
echo    MNc/MNb/MNa:      "return: forwarding" on responses
echo    SvcGW window:      "type=1 key='homepage'" on GET
echo    Client window:     response printed after GET
echo.
echo  NOTE: Neither MN2/3/SvcGW/MNb/MNa see the Client IP.
echo        Neither MNii/iii/SvcGW/MNy/MNx see the Sender IP.
