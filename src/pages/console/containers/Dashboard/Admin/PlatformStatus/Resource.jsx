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

import React, { Component } from 'react'
import { Text } from 'components/Base'

import styles from './index.scss'

// 用于渲染平台资源的组件信息,一般是三个内容,用这个Resource组件渲染三次.<div key={data.name} className={styles.resource}>相当于上一层的组件名,最后由Text渲染组件内容

export default class Resource extends Component {
  handleClick = () => {
    const { data, onClick } = this.props
    onClick(data.link)
  }

  render() {
    const { data, count } = this.props
    return (
      <div key={data.name} className={styles.resource}>
        <Text
          icon={data.icon}
          title={count || 0}
          description={count === '1' ? t(data.name) : t(`${data.name}_PL`)}
          onClick={data.link ? this.handleClick : null}
        />
      </div>
    )
  }
}
