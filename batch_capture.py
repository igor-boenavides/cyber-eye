from data_handler import PacketCapture
from analyzer import Analyzer
from config import settings

# parâmetros fixos
FILENAME = settings.capture_filename
DURATION = settings.capture_duration
NUM_RUNS = settings.num_runs

analyzer = Analyzer()

for i in range(NUM_RUNS):
    print(f"\n--- Execução {i+1}/{NUM_RUNS} ---\n")
    pc = PacketCapture(settings.interface, settings.capture_filter, FILENAME, DURATION, analyzer)
    pc.capture_and_save()

print("Capturas finalizadas!")
