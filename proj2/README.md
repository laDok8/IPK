
# IPK projekt - packet sniffer
## autor: Ladislav Dokoupil
CLI program pro výpis zachycených paketů v hexadecimální podobě, který
je vypisován na standardní výstup.

## přiklady spuštění

`./ipk-sniffer -i` výpis rozhraní k naslouchání.

`./ipk-sniffer -i NÁZEV`výpis jednoho odchyceného paketu.

`./ipk-sniffer -i NÁZEV --tcp --port 80 -n -1` výpis TCP paketů na portu 80 do ukončení programu.


## seznam odevzdaných souborů
* main.cpp
* README.md
* Makefile
* manual.pdf
