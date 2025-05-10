# Nyo-SNMP

Monitorowanie stanu urządzeń sieciowych za pomocą SNMP i Pythona.

* Krzysztof Hager 52687
* Krystian Harasymek 54152
* Krystian Galus 52676
* Michał Fuławka 52675

## Funkcje

- Dodawanie indywidualnych urządzeń do monitoringu
- Skanowanie klas IP w poszukiwaniu urządzeń wspierających SNMP
- Monitorowanie urządzeń w czasie rzeczywistym
- Odczyt stanu urządzeń

## Wymagania

- Python 3.7+
- Flask
- pysnmp
- SQLAlchemy
- Pozostałe zależności z pliku requirements.txt

## Uruchomienie

1. Sklonowanie repozytorium:

```
git clone https://github.com/Kszyszka/nyo-snmp.git
cd nyo-snmp
```

2. Instalacja wymaganych bibliotek:

```
pip install -r requirements.txt
```

3. Uruchomienie aplikacji:

```
python app.py
```

4. Otwórz przeglądarkę internetową i przejdź na stronę `http://127.0.0.1:5000`

## Copyright

Aplikacja została wykonana w ramach projektu zaliczeniowego na DSW, autorzy:

* Krzysztof Hager 52687
* Krystian Harasymek 54152
* Krystian Galus 52676
* Michał Fuławka 52675
