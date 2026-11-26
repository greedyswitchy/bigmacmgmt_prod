# Linux USB Monitoring Agent (Prototype)

Прототип агента мониторинга подключаемых USB-устройств для ОС Linux (detect-only).

## Возможности
- Первичная инвентаризация подключённых устройств через `/sys/bus/usb/devices`
- Мониторинг в реальном времени через поток событий `udev` (`udevadm monitor`)
- Классификация по USB класс-кодам (`ID_USB_INTERFACES` / `bInterfaceClass`)
- Склейка составных устройств по физическому порту (`DEVPATH`)
- Детект повторной энумерации (ZeroCD / DFU / BadUSB) и подозрительных комбинаций (HID + Storage/Net)
- Локальное персистентное хранилище событий и алертов в SQLite

## Запуск (Linux, .NET 8 SDK)
```bash
cd linux-agent
dotnet restore
dotnet run
```