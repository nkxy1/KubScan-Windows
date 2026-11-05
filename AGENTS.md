# Projektregeln

Bei jeder abgeschlossenen inhaltlichen Aenderung die Versionsnummer in `KubScan.cs` (`App.Version`) einmal erhoehen. Format: `v.MAJOR.MINOR.PATCH`. PATCH und MINOR laufen von 0 bis 99; bei 100 wird die Stelle auf 0 gesetzt und die vorherige Stelle um 1 erhoeht: `v.1.0.99` -> `v.1.1.0`, `v.1.99.99` -> `v.2.0.0`. Reine Builds und Testlaeufe erhoehen die Version nicht. Die Versionsnummer steht links direkt hinter KubScan mit genau einem Leerzeichen in IP- und mDNS-Ansicht. Oben rechts werden weder Theme-Name noch Sprachhinweis angezeigt.
