import shared_auth
from netbridge_agent import auth


def test_every_name_is_the_shared_auth_object_and_unique():
    assert len(auth.__all__) == len(set(auth.__all__))
    for name in auth.__all__:
        assert getattr(auth, name) is getattr(shared_auth, name), name
