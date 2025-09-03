# This module is part of PKGToolBox, developed by seregonwar. It is a translated and adapted version from C++ to Python, based on the original implementation made by HoppersPS4.
# Credit to HoppersPS4 
# repository link: https://github.com/HoppersPS4/Waste_Ur_Time

import os
import sys
import time
import random
import string
import shutil
import subprocess
from pathlib import Path
from packages import PackagePS4, PackagePS5, PackagePS3
import struct
import logging
import json
import pickle
import base64
import threading
import queue
import hashlib

class PS4PasscodeBruteforcer:
    def __init__(self):
        self.passcode_found = False
        self.found_passcode = ""
        self.last_used_passcode = ""
        self.package_name = ""
        self.package_cid = ""
        self.debug_mode = False
        self.silence_mode = False
        self.package = None
        # Resumable state
        self._rng = random.Random()
        self._attempts_done = 0
        self._stop = False
        self._state_path = None
        self._checkpoint_every_attempts = 1000
        self._checkpoint_every_seconds = 5
        self._last_checkpoint_ts = 0.0

    def generate_random_passcode(self, length=32):
        """Generate random passcode (legacy random)."""
        if self.debug_mode:
            return "00000000000000000000000000000000"

        # Usa lettere, numeri, - e _
        characters = string.ascii_letters + string.digits + "-_"
        return ''.join(self._rng.choice(characters) for _ in range(length))

    # ----------------------
    # Generatore deterministico no-overlap
    # ----------------------
    def _code_from_counter(self, counter: int, seed_bytes: bytes) -> str:
        """Deriva un passcode di 32 caratteri URL-safe dal contatore e seed.
        Usa SHA-256 -> base64 urlsafe e tronca a 32 senza padding. Deterministico.
        """
        # 16 byte per grande spazio (2^128) + seed per sessione
        ctr_bytes = counter.to_bytes(16, 'big', signed=False)
        digest = hashlib.sha256(seed_bytes + ctr_bytes).digest()
        b64 = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
        # Garantisce almeno 32 caratteri
        if len(b64) < 32:
            b64 = (b64 * ((32 // len(b64)) + 1))[:32]
        return b64[:32]

    def validate_passcode(self, passcode):
        """Validate passcode format"""
        # Verifica solo la lunghezza
        if len(passcode) != 32:
            raise ValueError("Passcode must be 32 characters long")
        
        return True

    # ----------------------
    # Integrazione orbis-pub-cmd.exe (PS4)
    # ----------------------
    def _find_orbis_pub_cmd(self) -> str | None:
        """Restituisce il percorso di orbis-pub-cmd.exe se presente in packages/ps3lib, altrimenti None."""
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            exe = os.path.normpath(os.path.join(base_dir, '..', 'packages', 'ps3lib', 'orbis-pub-cmd.exe'))
            if os.path.isfile(exe):
                return exe
        except Exception:
            pass
        return None

    def _orbis_validate(self, exe: str, pkg_path: str, passcode: str) -> tuple[bool, str]:
        """Esegue img_file_list per validare la passcode. Ritorna (ok, output)."""
        try:
            cmd = [exe, 'img_file_list', '--passcode', passcode, pkg_path]
            cwd = os.path.dirname(exe)
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
            out = (proc.stdout or '') + ("\n" + proc.stderr if proc.stderr else '')
            return (proc.returncode == 0, out.strip())
        except Exception as e:
            return (False, f"orbis validate error: {e}")

    def _orbis_extract(self, exe: str, pkg_path: str, out_dir: str, passcode: str) -> tuple[bool, str]:
        """Esegue img_extract per estrarre i file. Ritorna (ok, output)."""
        try:
            os.makedirs(out_dir, exist_ok=True)
            cmd = [exe, 'img_extract', '--passcode', passcode, pkg_path, out_dir]
            cwd = os.path.dirname(exe)
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=1800)
            out = (proc.stdout or '') + ("\n" + proc.stderr if proc.stderr else '')
            return (proc.returncode == 0, out.strip())
        except Exception as e:
            return (False, f"orbis extract error: {e}")

    def try_passcode(self, input_file, output_directory, passcode):
        """Try to decrypt with a specific passcode"""
        try:
            # Prima: determina il formato e, se PS4, prova orbis-pub-cmd per un check/estrazione veloce
            with open(input_file, "rb") as fp:
                magic = struct.unpack(">I", fp.read(4))[0]

            if magic == PackagePS4.MAGIC_PS4:
                # Prova orbis-pub-cmd se disponibile (solo per tentativi manuali/singoli)
                exe = self._find_orbis_pub_cmd()
                if exe:
                    if len(passcode) != 32:
                        return f"[-] Invalid passcode length: {len(passcode)}"
                    ok, msg = self._orbis_validate(exe, input_file, passcode)
                    if ok:
                        ok2, msg2 = self._orbis_extract(exe, input_file, output_directory, passcode)
                        if ok2:
                            self.passcode_found = True
                            self.found_passcode = passcode
                            return f"[+] Successfully decrypted (orbis) with passcode: {passcode}\n{msg2}"
                        # Se validata ma estrazione fallita, continua con fallback interno
                    # Se non ok o exe non presente, continua con fallback interno

            # Load package only if not already loaded or for a different file
            if not self.package or getattr(self.package, 'original_file', None) != input_file:
                if magic == PackagePS4.MAGIC_PS4:
                    self.package = PackagePS4(input_file)
                elif magic == PackagePS5.MAGIC_PS5:
                    self.package = PackagePS5(input_file)
                elif magic == PackagePS3.MAGIC_PS3:
                    self.package = PackagePS3(input_file)
                else:
                    return f"[-] Unknown PKG format: {magic:08X}"

            if not self.package.is_encrypted():
                self.package.extract_all_files(output_directory)
                return "[+] Package is not encrypted. Files extracted."

            try:
                # Validate only length to avoid extra overhead
                if len(passcode) != 32:
                    return f"[-] Invalid passcode length: {len(passcode)}"

                self.package.extract_with_passcode(passcode, output_directory)
                self.passcode_found = True
                self.found_passcode = passcode
                return f"[+] Successfully decrypted with passcode: {passcode}"
            except ValueError as e:
                return f"[-] Failed to decrypt with passcode: {str(e)}"

        except Exception as e:
            logging.error(f"Error trying passcode: {str(e)}")
            return f"[-] Error: {str(e)}"

    def brute_force_passcode(self, input_file, output_directory, progress_callback=None, manual_passcode=None, num_workers: int = 1, tested_callback=None, seed: int | None = None):
        """Brute force or try specific passcode"""
        self.ensure_output_directory(output_directory)
        self._state_path = self._get_state_path(input_file)
        self._stop = False
        num_workers = max(1, int(num_workers or 1))
        # Seed deterministico (persistente se riprende lo stato):
        # se non fornito, deriviamo da tempo + path
        if seed is None:
            seed_material = f"{input_file}|{time.time()}".encode('utf-8')
            seed_hash = hashlib.sha256(seed_material).digest()
        else:
            seed_hash = hashlib.sha256(str(int(seed)).encode('utf-8')).digest()

        try:
            # Determine package type and create appropriate instance
            with open(input_file, "rb") as fp:
                magic = struct.unpack(">I", fp.read(4))[0]
                if magic == PackagePS4.MAGIC_PS4:
                    self.package = PackagePS4(input_file)
                elif magic == PackagePS5.MAGIC_PS5:
                    self.package = PackagePS5(input_file)
                elif magic == PackagePS3.MAGIC_PS3:
                    self.package = PackagePS3(input_file)
                else:
                    return f"[-] Unknown PKG format: {magic:08X}"

            if not self.package.is_encrypted():
                self.package.extract_all_files(output_directory)
                return "[+] Package is not encrypted. Files extracted."

            if progress_callback:
                progress_callback("[+] Package is encrypted. Starting decryption...")

            # Se è fornito un passcode manuale, prova solo quello
            if manual_passcode:
                try:
                    self.validate_passcode(manual_passcode)
                    # Per il tentativo manuale, try_passcode proverà prima orbis (se PS4) poi il fallback interno
                    result = self.try_passcode(input_file, output_directory, manual_passcode)
                    if progress_callback:
                        progress_callback(result)
                    return result
                except ValueError as e:
                    return f"[-] Invalid passcode format: {str(e)}"

            # Prova a ripristinare lo stato precedente
            self._maybe_load_state(input_file, progress_callback)
            self._last_checkpoint_ts = time.time()

            # Progress tracking
            start_ts = time.time()
            last_report_ts = start_ts
            last_report_attempts = self._attempts_done
            last_test_emit_ts = start_ts

            if num_workers == 1:
                # Single-threaded fast path: reuse loaded package
                counter = 0
                while not self.passcode_found and not self._stop:
                    passcode = self._code_from_counter(counter, seed_hash)
                    self.last_used_passcode = passcode
                    self._attempts_done += 1

                    try:
                        # Directly attempt using the loaded package to avoid reload overhead
                        if len(passcode) == 32:
                            self.package.extract_with_passcode(passcode, output_directory)
                            self.passcode_found = True
                            self.found_passcode = passcode
                            if progress_callback:
                                progress_callback(f"[+] Successfully decrypted with passcode: {passcode}")
                            break
                        else:
                            if progress_callback and (self._attempts_done % 5000 == 0):
                                progress_callback(f"[-] Invalid passcode length: {len(passcode)}")
                    except ValueError as e:
                        # Only occasionally report failures to reduce UI overhead
                        if progress_callback and (self._attempts_done % 200 == 0):
                            progress_callback(f"[-] Failed attempt #{self._attempts_done}: {str(e)}")

                    # Emit tested passcode rate-limited
                    now = time.time()
                    if tested_callback and (self._attempts_done % 50 == 0 or (now - last_test_emit_ts) >= 0.1):
                        tested_callback(passcode)
                        last_test_emit_ts = now

                    # Periodic rate reporting and checkpoint
                    if now - last_report_ts >= 1.0:
                        delta_attempts = self._attempts_done - last_report_attempts
                        rate = delta_attempts / max(1e-9, (now - last_report_ts))
                        if progress_callback:
                            progress_callback(f"[~] Attempts: {self._attempts_done} | Rate: {rate:.0f}/s")
                        last_report_ts = now
                        last_report_attempts = self._attempts_done
                        self._maybe_checkpoint(progress_callback)
                    counter += 1
            else:
                # Multi-threaded deterministic: ogni worker ha (counter = worker_id; step = num_workers)
                stop_flag = threading.Event()

                def worker(worker_id: int):
                    # Each worker has its own package instance
                    try:
                        with open(input_file, "rb") as fp2:
                            magic2 = struct.unpack(">I", fp2.read(4))[0]
                            if magic2 == PackagePS4.MAGIC_PS4:
                                pkg = PackagePS4(input_file)
                            elif magic2 == PackagePS5.MAGIC_PS5:
                                pkg = PackagePS5(input_file)
                            elif magic2 == PackagePS3.MAGIC_PS3:
                                pkg = PackagePS3(input_file)
                            else:
                                return
                    except Exception:
                        return

                    counter_local = worker_id  # offset diverso per worker
                    step = num_workers
                    last_emit_local = time.time()
                    while not stop_flag.is_set() and not self._stop and not self.passcode_found:
                        code = self._code_from_counter(counter_local, seed_hash)
                        try:
                            if len(code) == 32:
                                pkg.extract_with_passcode(code, output_directory)
                                # Found!
                                self.passcode_found = True
                                self.found_passcode = code
                                stop_flag.set()
                                if progress_callback:
                                    progress_callback(f"[+] Successfully decrypted with passcode: {code}")
                                break
                        except ValueError:
                            pass
                        finally:
                            # Count attempts regardless of success
                            self._attempts_done += 1
                            # Emit tested code rate-limited per worker
                            now_l = time.time()
                            if tested_callback and (self._attempts_done % 100 == 0 or (now_l - last_emit_local) >= 0.15):
                                tested_callback(code)
                                last_emit_local = now_l
                        counter_local += step

                # Start producer and workers
                workers = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(num_workers)]
                for t in workers:
                    t.start()

                # Monitor loop for progress and exit conditions
                while not self.passcode_found and not self._stop:
                    now = time.time()
                    if now - last_report_ts >= 1.0:
                        delta_attempts = self._attempts_done - last_report_attempts
                        rate = delta_attempts / max(1e-9, (now - last_report_ts))
                        if progress_callback:
                            progress_callback(f"[~] Attempts: {self._attempts_done} | Threads: {num_workers} | Rate: {rate:.0f}/s")
                        last_report_ts = now
                        last_report_attempts = self._attempts_done
                        self._maybe_checkpoint(progress_callback)
                    time.sleep(0.05)

                stop_flag.set()

            if self.passcode_found:
                success_file_name = f"{input_file}.success"
                try:
                    with open(success_file_name, "w") as success_file:
                        success_file.write(self.found_passcode)
                    # Rimuovi lo stato salvato poiché abbiamo finito
                    try:
                        if self._state_path and os.path.exists(self._state_path):
                            os.remove(self._state_path)
                    except Exception:
                        pass
                    return f"[+] Passcode found: {self.found_passcode}\n[+] Passcode has been saved to: {success_file_name}"
                except Exception as e:
                    return f"[+] Passcode found: {self.found_passcode}\n[-] Failed to create/save the success file: {e}"
            else:
                # Salva lo stato anche in caso di stop o chiusura
                self._save_state(input_file)
                return "[-] Passcode not found or process stopped. Progress saved."

        except FileNotFoundError:
            return f"[-] Package file not found: {input_file}"
        except Exception as e:
            logging.error(f"Error during brute force: {str(e)}")
            return f"[-] Error: {str(e)}"

    def ensure_output_directory(self, output_directory):
        """Assicura che la directory di output esista"""
        os.makedirs(output_directory, exist_ok=True)

    def get_package(self):
        """Restituisce l'oggetto package corrente"""
        return self.package

    def set_debug_mode(self, enabled):
        """Imposta la modalità debug"""
        self.debug_mode = enabled

    def set_silence_mode(self, enabled):
        """Imposta la modalità silenziosa"""
        self.silence_mode = enabled

    def stop(self):
        """Richiedi l'arresto del processo di brute force"""
        self._stop = True

    # ----------------------
    # Stato e checkpointing
    # ----------------------
    def _get_state_path(self, input_file):
        """Restituisce il percorso del file di stato per l'input specificato"""
        return f"{input_file}.brutestate.json"

    def _maybe_load_state(self, input_file, progress_callback=None):
        try:
            if not self._state_path or not os.path.exists(self._state_path):
                return
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("input_file") != os.path.abspath(input_file):
                return
            state_b64 = data.get("rng_state_b64")
            if state_b64:
                rng_state = pickle.loads(base64.b64decode(state_b64.encode("utf-8")))
                self._rng.setstate(rng_state)
            self._attempts_done = int(data.get("attempts_done", 0))
            self.last_used_passcode = data.get("last_passcode", "")
            if progress_callback:
                progress_callback(f"[+] Resumed previous session: attempts={self._attempts_done}")
        except Exception as e:
            logging.error(f"Failed to load bruteforce state: {e}")

    def _maybe_checkpoint(self, progress_callback=None):
        try:
            now = time.time()
            if (self._attempts_done % self._checkpoint_every_attempts == 0) or (now - self._last_checkpoint_ts >= self._checkpoint_every_seconds):
                self._save_state(self.package.file_path if hasattr(self.package, 'file_path') else "")
                self._last_checkpoint_ts = now
                if progress_callback:
                    progress_callback(f"[+] Checkpoint saved: attempts={self._attempts_done}")
        except Exception as e:
            logging.error(f"Failed to checkpoint bruteforce state: {e}")

    def _save_state(self, input_file):
        try:
            if not self._state_path:
                self._state_path = self._get_state_path(input_file)
            data = {
                "version": 1,
                "input_file": os.path.abspath(input_file),
                "attempts_done": self._attempts_done,
                "last_passcode": self.last_used_passcode,
                "rng_state_b64": base64.b64encode(pickle.dumps(self._rng.getstate())).decode("utf-8"),
                "timestamp": time.time(),
            }
            with open(self._state_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save bruteforce state: {e}")
