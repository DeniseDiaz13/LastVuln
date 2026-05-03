from unittest.mock import patch, Mock
from lastvuln_cli.client import search_ecosystem


@patch("lastvuln_cli.client.requests.post")
def test_search_ecosystem_invalid(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {
        "errors": [
            {
                "extensions": {
                    "value": "NODE",
                    "problems": [
                        {
                            "path": [],
                            "explanation": 'Expected "NODE" to be one of: COMPOSER, ERLANG, ACTIONS, GO, MAVEN, NPM, NUGET, PIP, PUB, RUBYGEMS, RUST, SWIFT',
                        }
                    ],
                },
                "message": "Variable $ecosystem of type SecurityAdvisoryEcosystem! was provided invalid value",
            }
        ]
    }

    mock_post.return_value = mock_response

    result = search_ecosystem("NODE", 5)

    assert result == []
