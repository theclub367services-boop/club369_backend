from rest_framework.renderers import JSONRenderer

class StandardizedJSONRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = renderer_context.get('response')
        
        # Determine success based on status code
        success = response.status_code < 400
        
        # If data is already in the standardized format, return as is to avoid double wrapping
        if isinstance(data, dict) and 'success' in data and ('data' in data or 'errors' in data):
            # Ensure message exists
            if 'message' not in data:
                data['message'] = ""
            return super().render(data, accepted_media_type, renderer_context)

        # Standardize message
        message = ""
        # ... rest of the logic ...
        if isinstance(data, dict):
            message = data.pop('message', "")
            if not message:
                message = data.get('status', "")
                
            if not message and not success:
                message = data.get('error', data.get('detail', "An error occurred"))
        elif isinstance(data, list) and not success:
            if data and isinstance(data[0], str):
                message = data[0]
            else:
                message = "Validation error occurred"
        elif isinstance(data, str) and not success:
            message = data
        
        # Extract errors if not success
        errors = None
        if not success:
            errors = data
            if isinstance(data, dict) and ('error' in data or 'detail' in data):
                pass
        
        standardized_data = {
            'success': success,
            'message': str(message),
            'data': data if success else None,
            'errors': errors if not success else None
        }
        
        return super().render(standardized_data, accepted_media_type, renderer_context)
