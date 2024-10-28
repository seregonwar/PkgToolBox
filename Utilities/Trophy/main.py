import atexit
from TRPReader import TRPReader

trp_reader = TRPReader("/percorso/del/tuo/file.trp")
temp_dir = trp_reader.extract()

def cleanup_on_exit():
    if trp_reader:
        trp_reader.cleanup()

atexit.register(cleanup_on_exit)

# Analizza tutti i file ESFM
for archiver in trp_reader.trophy_list:
    if archiver.name.endswith('.ESFM'):
        analysis = trp_reader.get_esfm_analysis(archiver.name)
        if analysis:
            print(f"Analisi di {archiver.name}:")
            print(f"Dimensione: {analysis['size']}")
            print(f"Contenuto: {analysis['content'][:100]}...")  # Mostra i primi 100 caratteri

print(f"File estratti in: {temp_dir}")
print("Premi Invio per terminare il programma...")
input()