from data_handler import PacketCapture
from analyzer import Analyzer

# parâmetros fixos
INTERFACE = "Ethernet"
FILTER = ""  # vazio = captura tudo
FILENAME = "packets.csv"
DURATION = 240  # segundos por janela
NUM_RUNS = 100

analyzer = Analyzer()

for i in range(NUM_RUNS):
    print(f"\n--- Execução {i+1}/{NUM_RUNS} ---\n")
    pc = PacketCapture(INTERFACE, FILTER, FILENAME, DURATION, analyzer)
    pc.capture_and_save()

print("Capturas finalizadas!")
