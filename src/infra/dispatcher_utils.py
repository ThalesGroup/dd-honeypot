class DispatcherUtils:
    def __init__(self, backend_map):
        if not isinstance(backend_map, dict):
            raise TypeError("backend_map must be a dict of name:class")
        self.backends = backend_map

    def get_handler_descriptions(self):
        descriptions = {}
        for name, cls in self.backends.items():
            try:
                instance = cls()
                desc = getattr(instance, "description", None) or "No description"
            except Exception:
                desc = "No description"
            descriptions[name] = desc
        return descriptions

    @staticmethod
    def get_single_description(handler_cls):
        instance = handler_cls() if callable(handler_cls) else handler_cls
        return getattr(instance, "description", None) or "No description"
