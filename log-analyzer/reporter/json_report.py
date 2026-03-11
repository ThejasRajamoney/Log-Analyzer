import json

class JSONReporter:
    def __init__(self):
        pass
    
    def save(self, reports, output_file):
        if isinstance(reports, list):
            data = [r.to_dict() for r in reports]
        else:
            data = reports.to_dict()
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
