/*
 * This file is part of KubeSphere Console.
 * Copyright (C) 2019 The KubeSphere Console Authors.
 *
 * KubeSphere Console is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KubeSphere Console is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with KubeSphere Console.  If not, see <https://www.gnu.org/licenses/>.
 */

const isEmpty = require('lodash/isEmpty')
const jwtDecode = require('jwt-decode')
const omit = require('lodash/omit')
const base64_url_decode = require('jwt-decode/lib/base64_url_decode')
const { getServerConfig } = require('../libs/utils')

const { client: clientConfig } = getServerConfig()

const {
  login,
  loginThird,
  oAuthLogin,
  getNewToken,
  createUser,
} = require('../services/session')
const {
  isValidReferer,
  isAppsRoute,
  decryptPassword,
  safeParseJSON,
  safeBase64,
} = require('../libs/utils')

const { send_gateway_request } = require('../libs/request')

const handleLogin = async ctx => {
  // 从上下文中提取请求体，假定登录参数（如用户名、密码和加密细节）包含在请求体中。
  const params = ctx.request.body
  // 获取请求上下文中的 'referer' cookie，如果存在，则对其进行解码并存储在 referer 变量中。
  let referer = ctx.cookies.get('referer')
  referer = referer ? decodeURIComponent(referer) : ''

  const error = {}
  let user = null
  // 检查登录参数是否有效。如果无效，将使用详细信息填充 error 对象。
  if (isEmpty(params) || !params.username || !params.encrypt) {
    Object.assign(error, {
      status: 400,
      reason: 'Invalid Login Params',
      message: 'invalid login params',
    })
  }

  if (isEmpty(error)) {
    try {
      const encryptKey = clientConfig.encryptKey || 'kubesphere'
      //decryptPassword 函数一般用来解密加密过的密码。
      params.password = decryptPassword(params.encrypt, encryptKey)
      //调用login进行登录，返回用户信息
      user = await login(params, { 'x-client-ip': ctx.request.ip })

      if (!user) {
        Object.assign(error, {
          status: 401,
          reason: 'Unauthorized',
          message: 'INCORRECT_USERNAME_OR_PASSWORD',
        })
      }
    } catch (err) {
      ctx.app.emit('error', err)

      switch (err.code) {
        case 400:
        case 401:
          Object.assign(error, {
            status: err.code,
            reason: 'Unauthorized',
            message: 'INCORRECT_USERNAME_OR_PASSWORD',
          })
          break
        case 429:
          Object.assign(error, {
            status: err.code,
            reason: 'Too Many Failures',
            message: 'TOO_MANY_FAILURES',
          })
          break
        case 502:
          Object.assign(error, {
            status: err.code,
            reason: 'Bad Gateway',
            message: 'FAILED_TO_ACCESS_BACKEND',
          })
          break
        case 'ETIMEDOUT':
          Object.assign(error, {
            status: 500,
            reason: 'Internal Server Error',
            message: 'FAILED_TO_ACCESS_API_SERVER',
          })
          break
        default:
          Object.assign(error, {
            status: 500,
            reason: err.statusText,
            message: err.message,
          })
      }
    }
  }
  //登陆失败则返回错误参数
  if (!isEmpty(error) || !user) {
    ctx.body = error
    return
  }

  const lastToken = ctx.cookies.get('token')
  //设置新的 cookies，其中包括用户的新令牌（token）、过期时间（expire）、刷新令牌（refreshToken）。将 'referer' 设置为 null，可能是为了清除之前的 referer 信息。
  ctx.cookies.set('token', user.token)
  ctx.cookies.set('expire', user.expire)
  ctx.cookies.set('refreshToken', user.refreshToken)
  ctx.cookies.set('referer', null)
  //如果用户的用户名是 'system:pre-registration'，则使用安全的 Base64 编码将用户的 extraname 设置为 'defaultUser' cookie，并将用户的邮箱设置为 'defaultEmail' cookie。然后，重定向用户到 '/login/confirm' 页面。
  if (user.username === 'system:pre-registration') {
    const extraname = safeBase64.safeBtoa(user.extraname)
    ctx.cookies.set('defaultUser', extraname)
    ctx.cookies.set('defaultEmail', user.email)
    return ctx.redirect('/login/confirm')
  }
  //如果用户未初始化，即用户需要进一步设置密码等信息，将用户重定向到 '/password/confirm' 页面。
  if (!user.initialized) {
    return ctx.redirect('/password/confirm')
  }
  //如果存在上一次登录的 Token，解码该 Token 获取用户名。如果用户名存在且与当前登录用户的用户名不同，将用户重定向到根路径 '/'。
  if (lastToken) {
    const { username } = jwtDecode(lastToken)
    if (username && username !== user.username) {
      return ctx.redirect('/')
    }
  }

  ctx.redirect(isValidReferer(referer) ? referer : '/')
}

const handleThirdLogin = async ctx => {
  const params = ctx.request.body

  let referer = ctx.cookies.get('referer')
  referer = referer ? decodeURIComponent(referer) : ''

  const error = {}
  let user = null

  if (!params.username || !params.password) {
    Object.assign(error, {
      status: 400,
      reason: 'Invalid Login Params',
      message: 'invalid login params',
    })
  }

  if (isEmpty(error)) {
    try {
      user = await loginThird(params, { 'x-client-ip': ctx.request.ip })

      if (!user) {
        Object.assign(error, {
          status: 401,
          reason: 'Unauthorized',
          message: 'INCORRECT_USERNAME_OR_PASSWORD',
        })
      }
    } catch (err) {
      ctx.app.emit('error', err)

      switch (err.code) {
        case 400:
        case 401:
          Object.assign(error, {
            status: err.code,
            reason: 'Unauthorized',
            message: 'INCORRECT_USERNAME_OR_PASSWORD',
          })
          break
        case 429:
          Object.assign(error, {
            status: err.code,
            reason: 'Too Many Failures',
            message: 'TOO_MANY_FAILURES',
          })
          break
        case 502:
          Object.assign(error, {
            status: err.code,
            reason: 'Bad Gateway',
            message: 'FAILED_TO_ACCESS_BACKEND',
          })
          break
        case 'ETIMEDOUT':
          Object.assign(error, {
            status: 500,
            reason: 'Internal Server Error',
            message: 'FAILED_TO_ACCESS_API_SERVER',
          })
          break
        default:
          Object.assign(error, {
            status: 500,
            reason: err.statusText,
            message: err.message,
          })
      }
    }
  }

  if (!isEmpty(error) || !user) {
    ctx.body = error
    return
  }

  const lastToken = ctx.cookies.get('token')

  ctx.cookies.set('token', user.token)
  ctx.cookies.set('expire', user.expire)
  ctx.cookies.set('refreshToken', user.refreshToken)
  ctx.cookies.set('referer', null)

  if (user.username === 'system:pre-registration') {
    const extraname = safeBase64.safeBtoa(user.extraname)
    ctx.cookies.set('defaultUser', extraname)
    ctx.cookies.set('defaultEmail', user.email)
    return ctx.redirect('/login/confirm')
  }

  if (!user.initialized) {
    return ctx.redirect('/password/confirm')
  }

  if (lastToken) {
    const { username } = jwtDecode(lastToken)
    if (username && username !== user.username) {
      return ctx.redirect('/')
    }
  }

  ctx.redirect(isValidReferer(referer) ? referer : '/')
}

const handleLogout = async ctx => {
  const oAuthLoginInfo = safeParseJSON(
    decodeURIComponent(ctx.cookies.get('oAuthLoginInfo'))
  )

  const token = ctx.cookies.get('token')

  ctx.cookies.set('token', null)
  ctx.cookies.set('expire', null)
  ctx.cookies.set('refreshToken', null)
  ctx.cookies.set('oAuthLoginInfo', null)

  if (
    !isEmpty(oAuthLoginInfo) &&
    oAuthLoginInfo.type &&
    oAuthLoginInfo.type === 'OIDCIdentityProvider' &&
    oAuthLoginInfo.endSessionURL
  ) {
    const url = `${oAuthLoginInfo.endSessionURL}`
    ctx.body = { data: { url }, success: true }
  } else {
    const { origin = '', referer = '' } = ctx.headers
    const refererPath = referer.replace(origin, '')

    await send_gateway_request({
      method: 'GET',
      url: '/oauth/logout',
      token,
    })

    if (isAppsRoute(refererPath)) {
      ctx.redirect(refererPath)
    } else {
      ctx.redirect('/login')
    }
  }
}

const handleOAuthLogin = async ctx => {
  let user = null
  const error = {}
  const oauthParams = omit(ctx.query, ['redirect_url', 'state'])
  let referer = ctx.cookies.get('referer')
  referer = referer ? decodeURIComponent(referer) : ''

  try {
    user = await oAuthLogin({ ...oauthParams, oauthName: ctx.params.name })
  } catch (err) {
    /* eslint-disable no-console */
    console.log(err)

    ctx.app.emit('error', err)
    Object.assign(error, {
      status: err.code,
      reason: err.statusText,
      message: err.message,
    })
  }

  if (!isEmpty(error) || !user) {
    ctx.body = error
    return
  }

  ctx.cookies.set('token', user.token)
  ctx.cookies.set('expire', user.expire)
  ctx.cookies.set('refreshToken', user.refreshToken)
  ctx.cookies.set('referer', null)

  if (user.username === 'system:pre-registration') {
    const extraname = safeBase64.safeBtoa(user.extraname)
    ctx.cookies.set('defaultUser', extraname)
    ctx.cookies.set('defaultEmail', user.email)
    return ctx.redirect('/login/confirm')
  }

  const state = ctx.query.state
  const redirect_url = ctx.query.redirect_url

  if (state) {
    try {
      const state_object = JSON.parse(base64_url_decode(state))
      const state_url = state_object.redirect_url
      if (state_url) {
        ctx.redirect(state_url)
      }
    } catch (err) {
      /* eslint-disable no-console */
      console.log(err)
    }
  }

  if (redirect_url) {
    const redirectHost = new URL(redirect_url).host
    if (redirectHost === ctx.headers.host) {
      ctx.redirect(redirect_url)
    }
  } else {
    ctx.redirect(isValidReferer(referer) ? referer : '/')
  }
}

const handleLoginConfirm = async ctx => {
  const token = ctx.cookies.get('token')
  const params = ctx.request.body

  await createUser(params, token)

  const data = await getNewToken(ctx)
  if (data.token) {
    ctx.cookies.set('token', data.token)
    ctx.cookies.set('expire', data.expire)
    ctx.cookies.set('refreshToken', data.refreshToken)

    ctx.cookies.set('defaultUser', null)
    ctx.cookies.set('defaultEmail', null)
    ctx.redirect('/')
  }
}

module.exports = {
  handleLogin,
  handleThirdLogin,
  handleLogout,
  handleOAuthLogin,
  handleLoginConfirm,
}
