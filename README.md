# Welcome to Kite - a floating kernel

Kite is a Python program that implements the functionality of a unix operating system, by playing the role of a kernel. It runs on a host OS, while the user processes are executed on a processor emulator.

**Description (in Polish, English version in progress):**

Celem jest zaimplementowanie podstawowych funkcjonalności jądra systemu operacyjnego w wysokopoziomowym języku programowania Python. Taki program będzie zawierał wszystkie niezbędne struktury danych, potrzebne do utrzymywania stanu jądra, ale procesy użytkownika będą w rzeczywistości wykonywane na zewnętrznym emulatorze procesora. Będzie to możliwe dzięki odpowiedniemu interfejsowi, który będzie łączył program jądra z emulatorem. Emulator będzie udostępniał stan emulowanej maszyny, z kolei jądro na podstawie uzyskanych informacji będzie mogło podejmować decyzje i odpowiednio ten stan modyfikować. Tak więc kiedy ma wykonać się proces użytkownika, jądro tworzy potrzebne struktury danych, odpowiednio przygotowuje stan emulatora, po czym oddaje mu inicjatywę, a on rozpoczyna wykonywanie obliczeń procesu. Wykonuje je bez żadnej interwencji do momentu, aż coś się wydarza - przychodzi przerwanie do procesora, natrafiamy na syscall'a, pułapkę itp. - wtedy sterowanie przechodzi do jądra, które odpowiednio reaguje, po czym sterowanie wraca do emulatora.

Dobrze zaprojektowany interfejs będzie umożliwiał podmienianie emulatora na inne dostępne, przy względnie niskim nakładzie dodatkowej pracy.

Takie rozwiązanie pozwala na całkowicie nowe spojrzenie. Teraz bowiem świat jądra i świat userspace'u są zupełnie rozgraniczone. Userspace dzieje się na prawdziwej (emulowanej wprawdzie) maszynie, ale świat jądra jest całkowicie oderwany od wszelkiej artichetkury i hardware'u. Jest światem idei a nie zaglądania do sterowników i ręcznego przestawiania wskaźników.

**Kilka słów o motywacji:**

Jądro systemu operacyjnego to niezwykle skomplikowane oprogramowanie. Miliony linii kodu, którego nie sposób na raz ogarnąć, nawet koncepcyjnie, i którego rozszyfrowanie jest zupełnie niedostępne dla początkujących programistów. Tymczasem zrozumienie roli i zadań jądra, jest kluczowym aspektem zapoznawania się z systemami operacyjnymi. Skoro zaczynanie od analizowania prawdziwej implementacji nie ma sensu, trzeba zaczynać od opisów teoretycznych, wyjaśniając stopniowo idee poszczególnych rozwiązań.

W takiej sytuacji, bardzo korzystna byłaby również możliwość uczenia się na żywym kodzie, tak by móc naprawdę obejrzeć i dotknąć wszystkich istotnych mechanizmów i struktur danych. Taki trenażowy system operacyjny powinien oddawać rzeczywistość, to znaczy programy użytkownika powinny być prawdziwymi plikami binarnymi, uruchamianymi na rzeczywistej architekturze. Interesuje nas taka implementacja jądra, która spełnia ten warunek, ale sama odcina się od wszelkich niskich warstw, ponieważ ma obrazować mechanizmy istotne z punktu widzenie jądra jako zarządcy procesów użytkownika.
