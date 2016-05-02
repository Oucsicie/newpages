#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):
    email = StringField(u'电子邮件', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField(u'密码', validators=[Required()])
    remember_me = BooleanField(u'记住登录口令')
    submit = SubmitField(u'确认提交')


class RegistrationForm(Form):
    email = StringField(u'电子邮件', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField(u'账户名称', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField(u'密码', validators=[
        Required(), EqualTo('password2', message=u'两次密码输入必须相同.')])
    password2 = PasswordField(u'确认密码', validators=[Required()])
    submit = SubmitField(u'确认提交')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'电子邮件已经存在.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError(u'账户名称已经存在.')


class ChangePasswordForm(Form):
    old_password = PasswordField(u'旧密码', validators=[Required()])
    password = PasswordField(u'新密码', validators=[
        Required(), EqualTo('password2', message=u'两次密码输入必须相同')])
    password2 = PasswordField(u'确认新密码', validators=[Required()])
    submit = SubmitField(u'更新密码')


class PasswordResetRequestForm(Form):
    email = StringField(u'电子邮件', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField(u'重设电子邮件')


class PasswordResetForm(Form):
    email = StringField(u'电子邮件', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField(u'新密码', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField(u'确认新密码', validators=[Required()])
    submit = SubmitField(u'重设密码')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError(u'未知的邮件地址.')


class ChangeEmailForm(Form):
    email = StringField(u'新电子邮件', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField(u'密码', validators=[Required()])
    submit = SubmitField(u'更新电子邮件')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'电子邮件已经存在.')
