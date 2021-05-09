import json
from tlstest import tls_test
from flask import Flask
from flask_restful import Resource, Api, reqparse

app = Flask(__name__)
api = Api(app)


class TlsTest(Resource):
    def get(self):
        args = parser.parse_args()
        args = args['args'].split(' ')
        args.append('-j')
        out = tls_test(args)
        return json.loads(out)


api.add_resource(TlsTest, '/')
parser = reqparse.RequestParser()
parser.add_argument('args', type=str)

if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
