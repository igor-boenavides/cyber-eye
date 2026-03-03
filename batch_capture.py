from data_handler import PacketCapture
from analyzer import Analyzer
from config import settings

# parâmetros fixos
INTERFACE = settings.interface
FILTER = settings.capture_filter
FILENAME = "packets.csv"
DURATION = settings.capture_duration  # segundos por janela
NUM_RUNS = settings.num_runs

analyzer = Analyzer()

for i in range(NUM_RUNS):
    print(f"\n--- Execução {i+1}/{NUM_RUNS} ---\n")
    pc = PacketCapture(INTERFACE, FILTER, FILENAME, DURATION, analyzer)
    pc.capture_and_save()

print("Capturas finalizadas!")
