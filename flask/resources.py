from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required,
                                get_jwt_identity, get_raw_jwt)

from flask import request, make_response,jsonify, redirect
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
import re
import io
import os
from string import punctuation, digits
import pickle
import pgdb

parser = reqparse.RequestParser()
parser.add_argument('username', help='Kullanıcı adı girin!', required=True)
parser.add_argument('password', help='Kullanıcı şifresi girin!', required=True)


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': 'Kullanıcı: {} mevcut.'.format(data['username'])}

        new_user = UserModel(
            username=data['username'],
            password=UserModel.generate_hash(data['password'])
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Kullanıcı: {} oluşturuldu.'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'message': 'Bir hata oldu!'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'Kullanıcı: {} yok!'.format(data['username'])}

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Giriş yaptınız. {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Bilgiler yanlış!'}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Token iptal edildi!'}
        except:
            return {'message': 'Bir hata oldu!'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Yenilenen token iptal edildi!'}
        except:
            return {'message': 'Bir hata oldu!'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()


class TalepTahmin(Resource):
    @jwt_required
    def post(self):
        vec = open("models/SVM_Model_102Class", 'rb')
        loaded_model = pickle.load(vec)
        vec.close()

        txt = request.get_json()
        talep_aciklama = txt['talep_aciklama']
        print(talep_aciklama)
        print(txt)
        examples = talep_aciklama
        # Parametre olarak gelen text'e preprocessing yapıyoruz.
        examples = examples.lower()
        examples = examples.replace('\n', ' ')
        examples = re.sub(r'[a-zA-Z0-9-_.]+@[a-zA-Z0-9-_.]+', ' ', examples)
        examples = re.sub(r'@[A-Za-z0-9]+', ' ', examples)
        examples = re.sub(r'((25]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}', ' ', examples)
        examples = re.sub(r'[^\w\s]', ' ', examples)
        examples = re.sub(' +', ' ', examples)
        examples = [examples]

        from sklearn.feature_extraction.text import TfidfTransformer
        from sklearn.feature_extraction.text import TfidfVectorizer
        # print(str(examples[0]))
        data = str(examples[0])
        print(data)
        transform_model = pickle.load(open('models/SVM_TFIDF_New_Version', 'rb'))
        transformed_data = transform_model.transform(examples)
        predicted = loaded_model.predict(transformed_data)

        print(predicted)

        from datetime import datetime

        import numpy as np
        def talepKayitEt(x, txt):
            dt = datetime.now()
            conn = pgdb.Connection(
                    "host='localhost' port='---' dbname='test' user='postgres' password='-----'")
            cur = conn.cursor()
            postgres_insert_query = "INSERT INTO talepkayit (konuno, talepaciklama, postingdate) VALUES (%s,%s,%s)"

            record_to_insert = [int(x), txt, dt]
            cur.execute(postgres_insert_query, record_to_insert)
            conn.commit()

            cur.close()
            # Konu Numarasına Göre hangi Konu Onu Alalım
            deger = int(x)
            # print(deger)
            cur = conn.cursor()
            postgres_select_query = cur.execute('SELECT konuadi FROM talepkonulari WHERE konuid = %s;', (deger,))

            sonuc = cur.fetchone()
            print('Konu Adı: ', sonuc[0])
            conn.commit()
            cur.close()
            conn.close()
            # print("kayıt edildi.")
            return sonuc[0]

        sonucGonder = talepKayitEt(predicted, talep_aciklama)

        return jsonify({'talep_aciklama': str(sonucGonder)})
