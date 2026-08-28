class BaseDriver:
    def __init__(self, connection):
        self.connection = connection

    def get_version(self) -> str:
        raise NotImplementedError

    def get_model(self) -> str:
        return "Non Rilevato"

    def get_serial(self) -> str:
        """Chassis serial number, or "" when the platform does not expose it
        in a command the triage already runs."""
        return ""

    def get_backup_command(self) -> str:
        raise NotImplementedError
