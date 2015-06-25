c:
cd C:\BlueIris
C:\cygwin\bin\date >> reset.log

echo "%*" >> reset.log

B:\java\jre32.8.45\bin\java -version

B:\java\jre32.7\bin\java -jar B:/exp/cams/BlueIris/GvBi.jar %* 

if ERRORLEVEL 1 pause

rem pause