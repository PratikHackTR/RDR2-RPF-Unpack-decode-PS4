# RDR2 RPF8 Unpack / Decode — PS4

[English](#english) · [Türkçe](#türkçe)

Repository: https://github.com/PratikHackTR/RDR2-RPF-Unpack-decode-PS4

## English

A focused Python RPF8 reader and TFIT decoder recovered from **burakdemirph / PratikHackTR's RDR2 PS4 localization workflow**. It reads archive tables, decodes supported encrypted entries and decompresses supported payloads. It is **not** a translation, dubbing, repacking or PKG-building tool.

### What is included

- `rpf8_crypto.py`: portable adaptation of our recovered project decoder, with explicit paths, lazy dependency loading and a small CLI.
- `test_rpf8_crypto.py`: synthetic tests; no game assets are needed for these tests.
- No game files, ELF dumps, extracted key/table bytes, Oodle DLLs or translation assets.

### Features and boundaries

- RPF8 header and 24-byte entry-table parsing, including nonzero container offsets.
- PS4 TFIT/CBC decoding, including the recovered selective entry-range logic.
- Plain entries (`key=255`), raw DEFLATE (`codec=1`) and Oodle (`codec=2`, external runtime).
- Unwrapped nested archives through the Python API or explicit CLI offsets; no automatic recursive extraction.
- Entry filenames use index/hash/extension ID. Original filenames and directory trees are **not** reconstructed.
- Archive reads use seeks rather than loading entire RPFs into memory. Stored and decoded entries are capped at **64 MiB each**; peak RAM can be higher because buffers coexist. Large entries fail explicitly; they are not silently skipped as successful.
- Encrypted key tags `0..163` and alias `192 -> 163` are handled. Unsupported tags, including previously encountered tag **212**, are errors. This is not a universal RPF8 decoder for every platform/build.
- Resource output is the decoded payload: the 16-byte resource wrapper and trailing signature, when present, are not preserved. Signatures are stripped, **not authenticated**. This tool does not produce byte-identical repack-ready resource wrappers.
- Unknown codecs, invalid sizes and unsupported encrypted/wrapped nested archives are not claimed as supported.

### Requirements

Use **64-bit Python 3.10+**. Python dependencies are standard-library only; there is no `pip install` step. The Oodle DLL integration targets Windows x64.

For encrypted archives you must provide all three:

1. A decrypted PS4 game executable in **ELF** form from your own matching installation; encrypted SELF/PKG files are not accepted.
2. A private `key_locations.json` mapping the required Swage identifiers to **file offsets and byte sizes in that exact ELF**.
3. Swage's `src/games/rage/hashes/RDR2.h`, containing `RDR2_PS4_KEY_HASHES` and `RDR2_TFIT_TABLE_HASHES` in their original order. Obtain it from [0x1F9F1/Swage](https://github.com/0x1F9F1/Swage); it is not bundled here.

For codec 2, additionally supply your own compatible **64-bit Oodle runtime DLL** with `--oodle`. It is loaded only when a codec-2 entry is read. Loading a DLL executes native code; use a trusted local copy. Do not upload it with this project.

**Important: this package is the decoder, not the key-location scanner.** The original private ELF and location report were removed with the working game directory. The location map is not embedded or automatically generated here. Downloading this script alone therefore does not make encrypted archives readable. Missing prerequisites are reported explicitly.

Location map shape (illustration only; replace all placeholders with your locally verified report):

```json
{
  "<Swage PS4 key identifier>": {"offset": 0, "size": 320},
  "<Swage TFIT table identifier>": {"offset": 0, "size": 1024},
  "<Swage IV identifier>": {"offset": 0, "size": 16}
}
```

There must be locations for all 164 PS4 key identifiers, all 272 table identifiers and the IV lookup identifier used by the script. Zero offsets above are placeholders, **not usable values**. A location map for a different executable is not interchangeable. This version checks map ranges/sizes; it does not independently fingerprint the ELF or verify every key/table hash. A map passing structural checks is not proof of correct key material.

### Usage

Check the CLI and run synthetic tests:

```powershell
python rpf8_crypto.py --help
python -m unittest -v test_rpf8_crypto
```

List an unencrypted archive's entries:

```powershell
python rpf8_crypto.py list "D:\game\archive.rpf"
```

List an encrypted archive (listing its table does not decompress its entries):

```powershell
python rpf8_crypto.py list "D:\game\common_0.rpf" --elf "D:\private\base_eboot.elf" --locations "D:\private\key_locations.json" --swage-header "D:\Swage\src\games\rage\hashes\RDR2.h"
```

Extract a selected entry, or omit `--index` to attempt all non-directory entries in that archive:

```powershell
python rpf8_crypto.py extract "D:\game\common_0.rpf" --index 0 --out "D:\output\common-entry-0" --elf "D:\private\base_eboot.elf" --locations "D:\private\key_locations.json" --swage-header "D:\Swage\src\games\rage\hashes\RDR2.h" --oodle "D:\private\oo2core_8_win64.dll"
```

`--out` must be a **new directory**. Inputs are opened read-only and existing extraction directories are not reused. A `report.json` records successes/failures; exit code 1 means an error or partial extraction, not full success. Check disk space before extracting; this small standalone tool has no aggregate output-size quota or power-loss resume database.

For a nested unwrapped archive use `--offset 0x... --size 0x...`. These are the **absolute offset in the source file** and the nested archive's logical size; use verified inventory values, not guesses. Python callers can instead use `archive.nested(entry)`.

### Provenance and validation

The original project decoder was used during an RDR2 PS4 **CUSA03041**, base **01.00**, update **01.32** localization workflow. The original code was recovered from local development history after the working directory was deleted. This release retains that core logic, replaces machine-specific paths, adds CLI/bounds/error handling and makes Oodle loading optional.

The cleaned portable release is covered by synthetic tests only at preparation time. The original game/ELF/key-location material was no longer available for a fresh encrypted-game integration test. Do not mistake the earlier workflow's results for validation of every code path in this adapted release, or for compatibility with all RDR2 versions.

### Credits and license

- Project-specific Python implementation, integration and PS4 localization workflow: **burakdemirph / PratikHackTR**.
- Format, PS4 key-identifier and TFIT reference work: **0x1F9F1 and Swage contributors**, [Swage](https://github.com/0x1F9F1/Swage), particularly `src/games/rage/hashes/RDR2.h`. This is not a claim that TFIT/RPF8 research was invented entirely by this project.
- Oodle is an external proprietary dependency; its code/binaries are not included or licensed by this project.

The destination repository already contains a GPL-3.0 license. Keep that repository's `LICENSE` when uploading these files. Third-party assets and dependencies retain their own terms; this README does not grant rights to redistribute them. No Rockstar game assets are bundled, and this project is not affiliated with Rockstar Games.

---

## Türkçe

**burakdemirph / PratikHackTR'nin RDR2 PS4 yerelleştirme çalışmasından kurtarılan**, Python tabanlı RPF8 okuyucu ve TFIT çözücüdür. Arşiv tablosunu okur, desteklenen şifreli girdileri çözer ve sıkıştırılmış içerikleri açar. Çeviri, dublaj, geri paketleme veya PKG derleme aracı değildir.

### İçerik ve destek

- `rpf8_crypto.py`: geçmişten kurtarılan decoder'ın açık dosya yolları, isteğe bağlı DLL yükleme ve komut satırı eklenmiş taşınabilir uyarlaması.
- `test_rpf8_crypto.py`: oyun dosyası gerektirmeyen sentetik testler.
- RPF8 başlık/TOC okuma, PS4 TFIT/CBC ve seçici şifreli aralıkların çözümü.
- Şifresiz içerik, raw DEFLATE ve harici DLL ile Oodle açma.
- Sarılmamış iç arşivlere API veya doğrulanmış ofsetlerle erişim; otomatik özyinelemeli çıkarma yoktur.
- Dosyalar indeks/hash/uzantı kimliğiyle adlandırılır; özgün dosya adları ve klasör yapısı geri getirilmez.
- Arşivin tamamı RAM'e alınmaz. Sıkıştırılmış ve açılmış tek girdi başına sınır **64 MiB**; eşzamanlı tamponlar nedeniyle toplam RAM bundan yüksek olabilir.
- Anahtar etiketleri `0..163` ve `192 -> 163` desteklenir. Önceki çalışmada karşılaşılan **212** gibi diğer etiketler açık hata verir. Tüm platformlar/sürümler için evrensel çözücü değildir.
- Kaynak girdilerde 16 baytlık resource sarmalayıcı ve varsa sondaki imza çıkarılır. İmza doğrulaması yapılmaz; çıktı birebir geri paketlemeye hazır özgün resource dosyası olarak sunulmaz.

### Gereken özel dosyalar

**64-bit Python 3.10+** kullanın. Python paketi kurmak gerekmez; standart kütüphane yeterlidir. Oodle bağlantısı Windows x64 içindir.

Şifreli arşivler için:

1. Kendi kurulumunuzla eşleşen, şifresi çözülmüş PS4 **ELF** dosyası.
2. Aynı ELF içindeki gerçek dosya ofsetlerini ve boyutlarını içeren özel **`key_locations.json`**.
3. [Swage](https://github.com/0x1F9F1/Swage) içindeki **`src/games/rage/hashes/RDR2.h`**; tanımların sırası korunmalıdır.

Codec 2 için ayrıca kendinizin sağladığı uyumlu 64-bit Oodle DLL'si gerekir. DLL yalnızca gerektiğinde yüklenir; güvenilir bir yerel kopya kullanın.

**Bu paket anahtar/ofset bulma aracı değildir.** Eski ELF ve konum raporu silinen oyun çalışma klasöründeydi. Bunlar pakete gömülmedi ve bu script bunları otomatik üretmez. Decoder dosyasını tek başına indirmek, şifreli arşivi açmak için yeterli değildir. Map biçimi ve eksiksiz örnek komutlar yukarıdaki İngilizce bölümündedir; örnekteki sıfır ofsetler gerçek değer değildir.

Map'te 164 PS4 anahtarı, 272 TFIT tablosu ve IV kimliğinin konumları gerekir. Başka ELF'ye ait map kullanmayın. Bu sürüm ofset/boyut sınırlarını denetler; ELF kimliğini ve tüm anahtar/tablo hash'lerini bağımsız doğrulamaz.

### Kullanım ve sınırlar

Yukarıdaki `list` ve `extract` komutlarını kullanın. `extract --index N` tek girdi çıkarır; `--index` verilmezse arşivdeki klasör dışı girdilerin tamamı denenir. `--out` daha önce var olmayan yeni bir klasör olmalıdır. Girdi arşivleri salt okunur açılır.

`report.json` hataları kaydeder; çıkış kodu **1**, hata veya kısmi çıkarma demektir. Toplam çıktı kotası ve elektrik kesintisinden devam sistemi bu küçük bağımsız araçta yoktur; disk alanını önceden kontrol edin. İç arşivlerde `--offset` kaynak dosyaya göre **mutlak** ofsettir; göreli ofseti doğrudan vermeyin.

Eski decoder, **CUSA03041 / ana oyun 01.00 / güncelleme 01.32** yerelleştirmesinde kullanıldı. Bu taşınabilir uyarlama hazırlanırken oyun, ELF ve özel konum haritası artık mevcut değildi; yeni bir gerçek şifreli oyun testi yapılmadı. Sentetik testlerin geçmesi bütün sürümlerin veya TFIT/Oodle gerçek oyun yolunun yeniden doğrulandığı anlamına gelmez.

### Emeği geçenler ve lisans

- Projeye özel Python uygulaması, entegrasyon ve PS4 yerelleştirme çalışması: **burakdemirph / PratikHackTR**.
- RPF8/TFIT ve PS4 tanım referansları: **0x1F9F1 ve Swage katkıcıları**. Çalışma, tüm format/kriptografi araştırmasının yalnızca bu projede sıfırdan icat edildiği iddiasını taşımaz.
- Oodle harici, özel mülkiyetli bağımlılıktır; DLL ve kaynakları bu pakette yoktur.

Hedef GitHub deposundaki mevcut **GPL-3.0 `LICENSE`** dosyasını koruyun. Üçüncü taraf dosyaların hakları kendi sahiplerindedir. Oyun arşivlerini, ELF'yi, çıkarılmış anahtar/tablo verilerini, özel map'i veya Oodle DLL'sini depoya yüklemeyin. Bu proje Rockstar Games ile bağlantılı değildir.
