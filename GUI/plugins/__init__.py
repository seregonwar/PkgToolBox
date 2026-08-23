import os
import importlib
import logging

class PluginManager:
    def __init__(self):
        self.plugins = {}
        self.plugin_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        self.load_plugins()
    
    def load_plugins(self):
        """Load all plugins from plugins directory"""
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            
        for file in os.listdir(self.plugin_dir):
            if file.endswith('.py') and not file.startswith('_'):
                try:
                    module_name = file[:-3]
                    spec = importlib.util.spec_from_file_location(
                        module_name, 
                        os.path.join(self.plugin_dir, file)
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    if hasattr(module, 'register_plugin'):
                        plugin = module.register_plugin()
                        self.plugins[plugin.name] = plugin
                        logging.info(f"Loaded plugin: {plugin.name}")
                except Exception as e:
                    logging.error(f"Failed to load plugin {file}: {str(e)}") 