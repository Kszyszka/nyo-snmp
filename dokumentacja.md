# SNMP Network Monitor - Instrukcja użytkowania

## Wprowadzenie

SNMP Network Monitor to aplikacja webowa służąca do monitorowania urządzeń sieciowych poprzez protokół SNMP. Program pozwala na śledzenie stanu urządzeń, ich wykorzystania zasobów oraz otrzymywanie powiadomień o zmianach statusu.

## Wymagania systemowe

- Python 3.x
- Przeglądarka internetowa z obsługą powiadomień
- Dostęp do urządzeń przez protokół SNMP
- Uprawnienia administratora (dla niektórych funkcji)

## Instalacja

1. Sklonuj repozytorium
2. Zainstaluj wymagane zależności:
   ```bash
   pip install -r requirements.txt
   ```
3. Uruchom aplikację:
   ```bash
   python app.py
   ```
4. Otwórz przeglądarkę i przejdź pod adres: `http://localhost:5000`

## Interfejs użytkownika

### Panel główny

- **Nagłówek**: Zawiera tytuł aplikacji, interwał sprawdzania i przycisk "Check All"
- **Formularz dodawania urządzenia**: Pozwala na dodanie pojedynczego urządzenia
- **Formularz skanowania zakresu IP**: Umożliwia skanowanie całego zakresu adresów IP
- **Tabela urządzeń**: Wyświetla listę wszystkich monitorowanych urządzeń

### Panel powiadomień

- Znajduje się po prawej stronie ekranu
- Pokazuje listę nieaktywnych urządzeń
- Wyświetla "Wszystko śmiga!" gdy wszystkie urządzenia są aktywne

## Dodawanie urządzeń

### Dodawanie pojedynczego urządzenia

1. Wypełnij formularz "Add New Device":
   - Wprowadź adres IP urządzenia
   - Opcjonalnie zmień społeczność SNMP (domyślnie "public")
2. Kliknij przycisk "Add Device"

### Skanowanie zakresu IP

1. Wypełnij formularz "Scan IP Range":
   - Wprowadź zakres IP w formacie CIDR (np. 192.168.1.0/24)
   - Opcjonalnie zmień społeczność SNMP
2. Kliknij przycisk "Scan Range"
3. Obserwuj postęp skanowania:
   - Liczba znalezionych aktywnych adresów IP
   - Postęp skanowania
   - Liczba znalezionych urządzeń SNMP

## Monitorowanie urządzeń

### Informacje wyświetlane dla każdego urządzenia

- Status (aktywne/nieaktywne)
- Nazwa urządzenia
- Czas pracy (uptime)
- Wykorzystanie CPU
- Wykorzystanie pamięci RAM
- Czas ostatniego sprawdzenia

### Funkcje monitorowania

- **Automatyczne sprawdzanie**: Program regularnie sprawdza status urządzeń
- **Ręczne sprawdzanie**: Możliwość sprawdzenia pojedynczego urządzenia
- **Sprawdzanie wszystkich**: Przycisk "Check All" do jednoczesnego sprawdzenia wszystkich urządzeń

## Zarządzanie urządzeniami

### Usuwanie urządzeń

- **Usuwanie pojedynczego urządzenia**: Kliknij ikonę kosza przy urządzeniu
- **Usuwanie wielu urządzeń**:
  1. Zaznacz urządzenia za pomocą checkboxów
  2. Kliknij przycisk "Delete Selected"

### Filtrowanie i wyszukiwanie

- Użyj pola wyszukiwania do filtrowania po IP lub nazwie
- Użyj menu rozwijanego "Filter" do filtrowania po statusie

## Powiadomienia

### Konfiguracja powiadomień

1. Przy pierwszym uruchomieniu przeglądarka poprosi o zgodę na powiadomienia
2. Kliknij "Allow" aby włączyć powiadomienia

### Rodzaje powiadomień

- Powiadomienia o zmianie statusu urządzenia na nieaktywny
- Powiadomienia w panelu bocznym
- Testowanie powiadomień: Kliknij przycisk "Test Notifications"

## Konfiguracja

### Interwał sprawdzania

1. Wprowadź nowy interwał w sekundach
2. Kliknij "Update"
3. Zmiany zostaną zastosowane natychmiast

### Społeczność SNMP

- Można ustawić różne społeczności SNMP dla różnych urządzeń
- Domyślna wartość to "public"

## Autorzy:

* Krzysztof Hager 52687
* Krystian Harasymek 54152
* Krystian Galus 52676
* Michał Fuławka 52675
