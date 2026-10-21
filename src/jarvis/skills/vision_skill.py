import ctypes
from pathlib import Path
import pyautogui
import pytesseract

from PIL import Image, ImageDraw, ImageEnhance, ImageOps


# Configuración de la ruta del binario de Tesseract para Windows
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'


class VisionSkill:
    def __init__(self, output_dir: str = "memory/captures"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.last_ocr_text = ""
        self.last_ocr_elements = []
        
        # Configurar ruta de tesseract en Windows si es necesario:
        # pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

    def tomar_captura_pantalla(self, nombre_archivo: str = "screenshot.png") -> str:
        """
        Toma una captura de todo el escritorio, la optimiza
        y extrae todo su texto mediante OCR local. Devuelve la ruta como STRING.
        """
        try:
            file_path = self.output_dir / nombre_archivo
            # Capture the entire virtual desktop, not only the focused window.
            # This is CPU-side and the resize below bounds OCR/VLM work, so it
            # does not add a persistent GPU load.
            desktop_screenshot = pyautogui.screenshot(allScreens=True)
            original_width, original_height = desktop_screenshot.size

            # ImageGrab uses the virtual desktop's top-left as the image origin.
            # Preserve that origin so OCR boxes still map to physical screen
            # coordinates when a secondary monitor has a negative position.
            try:
                offset_x = ctypes.windll.user32.GetSystemMetrics(76)  # SM_XVIRTUALSCREEN
                offset_y = ctypes.windll.user32.GetSystemMetrics(77)  # SM_YVIRTUALSCREEN
            except (AttributeError, OSError):
                offset_x, offset_y = 0, 0

            # Optimización de nitidez para el VLM local
            # Subimos de 1600 a 2048 para no destruir el texto de pantallas grandes
            # Optimización de nitidez para el VLM local
            screenshot = desktop_screenshot.copy()
            max_dimension = 2048
            if screenshot.width > max_dimension or screenshot.height > max_dimension:
                screenshot.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)

            # OCR receives a sharper CPU-side copy. This preserves small UI
            # labels while the image sent to the VLM remains lightweight.
            ocr_screenshot = desktop_screenshot.copy()
            max_ocr_dimension = 3072
            if (
                ocr_screenshot.width > max_ocr_dimension
                or ocr_screenshot.height > max_ocr_dimension
            ):
                ocr_screenshot.thumbnail(
                    (max_ocr_dimension, max_ocr_dimension),
                    Image.Resampling.LANCZOS,
                )

            # Map OCR coordinates to the VLM image and to the physical desktop.
            ocr_scale_x = ocr_screenshot.width / original_width
            ocr_scale_y = ocr_screenshot.height / original_height
            ocr_to_display_x = ocr_screenshot.width / screenshot.width
            ocr_to_display_y = ocr_screenshot.height / screenshot.height

            # Preparamos el lienzo para dibujar sobre la captura
            draw = ImageDraw.Draw(screenshot)

            # --- EXTRACCIÓN OCR EN DOS FASES: LÍNEAS Y COLUMNAS ---
            try:
                gray_image = screenshot.convert('L')
                custom_config = r'--psm 6'
                data_ocr = pytesseract.image_to_data(
                    gray_image,
                    output_type=pytesseract.Output.DICT,
                    lang='spa+eng',
                    config=custom_config,
                )
                palabras = []
                for i, raw_text in enumerate(data_ocr['text']):
                    text = raw_text.strip()
                    if not text or float(data_ocr['conf'][i]) < 20:
                        continue

                    x1 = data_ocr['left'][i]
                    y1 = data_ocr['top'][i]
                    palabras.append({
                        "text": text,
                        "x1": x1,
                        "y1": y1,
                        "x2": x1 + data_ocr['width'][i],
                        "y2": y1 + data_ocr['height'][i],
                    })

                # Fase vertical: agrupar palabras con una altura similar.
                palabras.sort(key=lambda palabra: (palabra['y1'], palabra['x1']))
                lineas = []
                for palabra in palabras:
                    linea = next(
                        (linea for linea in reversed(lineas)
                         if abs(palabra['y1'] - linea['y1']) < 8),
                        None,
                    )
                    if linea is None:
                        lineas.append({"y1": palabra['y1'], "palabras": [palabra]})
                    else:
                        linea['palabras'].append(palabra)

                # Fase horizontal: un hueco mayor de 30 píxeles inicia otra caja.
                lineas_agrupadas = []
                for linea in sorted(lineas, key=lambda item: item['y1']):
                    bloque_actual = None
                    for palabra in sorted(linea['palabras'], key=lambda item: item['x1']):
                        if bloque_actual is None:
                            bloque_actual = palabra.copy()
                            continue

                        espacio = palabra['x1'] - bloque_actual['x2']
                        if espacio > 30:
                            lineas_agrupadas.append(bloque_actual)
                            bloque_actual = palabra.copy()
                            continue

                        bloque_actual['text'] += " " + palabra['text']
                        bloque_actual['x1'] = min(bloque_actual['x1'], palabra['x1'])
                        bloque_actual['y1'] = min(bloque_actual['y1'], palabra['y1'])
                        bloque_actual['x2'] = max(bloque_actual['x2'], palabra['x2'])
                        bloque_actual['y2'] = max(bloque_actual['y2'], palabra['y2'])

                    if bloque_actual is not None:
                        lineas_agrupadas.append(bloque_actual)

                # 3. Procesar para el router y dibujar en la imagen
                self.last_ocr_elements = []
                for elem in lineas_agrupadas:
                    display_x1 = round(elem['x1'] / ocr_to_display_x)
                    display_y1 = round(elem['y1'] / ocr_to_display_y)
                    display_x2 = round(elem['x2'] / ocr_to_display_x)
                    display_y2 = round(elem['y2'] / ocr_to_display_y)
                    # Clasificación por zonas (Izquierda, Centro, Derecha)
                    if elem['x1'] < (ocr_screenshot.width / 3):
                        zona = "IZQUIERDA"
                    elif elem['x1'] > (ocr_screenshot.width * 2 / 3):
                        zona = "DERECHA"
                    else:
                        zona = "CENTRO"
                        
                    self.last_ocr_elements.append({
                        "text": elem['text'], 
                        "box": (
                            round(elem['x1'] / ocr_scale_x) + offset_x,
                            round(elem['y1'] / ocr_scale_y) + offset_y,
                            round((elem['x2'] - elem['x1']) / ocr_scale_x),
                            round((elem['y2'] - elem['y1']) / ocr_scale_y),
                        ),
                        "zona": zona,
                        "y_coord": elem['y1'],
                        "x_coord": elem['x1'],
                    })
                    
                    # Add a small margin so the outline does not cover glyphs.
                    padding = 3
                    draw.rectangle(
                        [
                            max(0, display_x1 - padding),
                            max(0, display_y1 - padding),
                            min(screenshot.width - 1, display_x2 + padding),
                            min(screenshot.height - 1, display_y2 + padding),
                        ],
                        outline="red",
                        width=2,
                    )
                
                # Ordenamos de arriba a abajo y estructuramos
                self.last_ocr_elements.sort(key=lambda item: (item['y_coord'], item['x_coord']))
                self.last_ocr_text = "\n".join([f"[{elem['zona']}] {elem['text']}" for elem in self.last_ocr_elements])
                
                print(f" > [VISION + OCR] Captura analizada, reducida a {len(self.last_ocr_elements)} bloques limpios.")
                
            except Exception as ocr_err:
                print(f" > [AVISO] Tesseract no detectado ({ocr_err}). Operando sin anclaje visual.")
                self.last_ocr_text = ""
                self.last_ocr_elements = []

            screenshot.save(file_path)
            return str(file_path)
        except Exception as err:
            print(f" > [ERROR] No se pudo tomar la captura: {err}")
            return ""
