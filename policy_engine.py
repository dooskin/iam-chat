from database import db
from models import Permission, Resource, User

def evaluate_access_request(user_id, resource_name, action):
    """
    Evaluates if a user has permission to perform an action on a resource
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return {'allowed': False, 'reason': 'User not found'}

        resource = Resource.query.filter_by(name=resource_name).first()
        if not resource:
            return {'allowed': False, 'reason': 'Resource not found'}

        permission = Permission.query.filter_by(
            role=user.role,
            resource_id=resource.id,
            action=action
        ).first()

        if permission:
            return {
                'allowed': True,
                'reason': f'Access granted for {action} on {resource_name}'
            }
        else:
            return {
                'allowed': False,
                'reason': f'No permission for {action} on {resource_name}'
            }

    except Exception as e:
        return {'allowed': False, 'reason': f'Error evaluating access: {str(e)}'}
