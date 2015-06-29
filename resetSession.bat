c:
cd C:\BlueIris
C:\cygwin\bin\date >> reset.log

echo "%*" >> reset.log

if exist lock goto :skip
C:\cygwin\bin\date > lock

B:\java\jre32.7\bin\java -jar B:/exp/cams/BlueIris/GvBi.jar %* 

if ERRORLEVEL 1 pause

rm -f lock
:skip
rem pause