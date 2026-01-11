@echo off
echo ================================================
echo   Backend Quick Test
echo ================================================
echo.

echo [1] Testing health endpoint...
curl http://localhost:8000/health
echo.
echo.

echo [2] Testing command execution...
curl -X POST http://localhost:8000/api/v1/execute ^
  -H "Authorization: Bearer valid_token" ^
  -H "Content-Type: application/json" ^
  -d "{\"command\":\"echo Hello\",\"context\":\"local\"}"
echo.
echo.

echo [3] Testing TLE sync...
curl -X POST http://localhost:8000/api/v1/orbital/sync ^
  -H "Authorization: Bearer valid_token" ^
  -H "Content-Type: application/json" ^
  -d "{\"group\":\"active\",\"source\":\"celestrak\"}"
echo.
echo.

echo [4] Testing CCSDS forge...
curl -X POST http://localhost:8000/api/v1/forge/ccsds ^
  -H "Authorization: Bearer valid_token" ^
  -H "Content-Type: application/json" ^
  -d "{\"apid\":1,\"transmit\":false,\"hex_payload\":\"DEADBEEF\",\"chaff\":false}"
echo.
echo.

echo ================================================
echo   Tests Complete
echo ================================================
pause
