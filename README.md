# SurveyGate - 企业级问卷认证与分发系统

[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![LimeSurvey](https://img.shields.io/badge/LimeSurvey-API%20Integration-orange.svg)](https://www.limesurvey.org/)

## 🚀 项目简介

SurveyGate 是一款专为企业环境设计的问卷调查认证网关系统，解决了 LimeSurvey 在企业内部使用时缺乏统一用户认证的痛点。系统通过 Flask 开发，无缝集成 LimeSurvey API，为内部用户提供统一的问卷访问入口和认证体系。

> **为什么选择 SurveyGate？**
> - ✅ 无需编写复杂的 LimeSurvey PHP 插件
> - ✅ 符合国内企业用户登录习惯
> - ✅ 保持 LimeSurvey 原生的问卷体验
> - ✅ 简化用户访问流程，提升填写体验

## ✨ 核心特性

### 👥 用户功能
- **统一认证登录** - 企业AD风格登录界面
- **问卷集中访问** - 查看所有可参与问卷
- **智能Token分发** - 自动生成LimeSurvey访问令牌
- **防重复机制** - 确保每个用户每份问卷只能作答一次
- **自助密码管理** - 用户可自行修改密码

### ⚙️ 管理功能
- **用户体系管理** - 完整的用户CRUD操作
- **批量用户导入** - 支持CSV格式批量导入
- **问卷生命周期管理** - 添加、编辑、启用/禁用问卷
- **LimeSurvey无缝集成** - 可视化API配置界面
- **数据统计看板** - 实时查看系统使用情况

## 🏗️ 系统架构

```
用户请求 → Nginx(反向代理) → SurveyGate(Flask应用) → LimeSurvey API
   ↑                             ↓
   └────── 企业用户认证 ←──── SQLite数据库
```

## 🛠️ 技术栈

- **后端框架**: Flask 2.0+
- **前端模板**: HTML5 + CSS3 (未引用CDN资源，方便内网部署)
- **数据存储**: SQLite (轻量级，易于部署)
- **API集成**: LimeSurvey RemoteControl API
- **部署方案**: Docker + Nginx反向代理

## 📦 快速部署

### 方式一：Docker Compose 一键部署(推荐)

我们提供了完整的 `docker-compose.yaml` 文件，包含 LimeSurvey 和 SurveyGate 的完整环境：

部署LimeSurvey，项目提供docker-compose.yaml文件，可直接部署LimeSurvey。

部署SurveyGate

修改app.py中LimeSurvey参数。

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 初始化应用
python app.py

# 3. 访问系统
#    用户端: http://localhost:5000
#    管理端: http://localhost:5000/admin
#    默认管理员: admin / admin123
```

## 🌐 Nginx 反向代理配置

 项目提供`nginx.conf` 配置文件


```

部署命令：
```bash
sudo cp nginx.conf /etc/nginx/sites-available/surveygate
sudo ln -s /etc/nginx/sites-available/surveygate /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 🔧 系统配置

### LimeSurvey API 连接设置

1. 使用管理员账号登录 SurveyGate
2. 进入"系统配置" → "LimeSurvey 设置"
3. 填写API端点：`http://limesurvey:8000/admin/remotecontrol`
4. 输入LimeSurvey管理员账号和密码
5. 测试连接并保存配置

### 用户导入格式

准备CSV文件（无表头）：
```
username1,password1
username2,password2
username3,password3
```

## 📋 API接口一览

### 用户侧接口
| 端点 | 方法 | 描述 | 权限 |
|------|------|------|------|
| `/` | GET/POST | 用户登录页面 | 公开 |
| `/dashboard` | GET | 用户问卷仪表板 | 需登录 |
| `/start_survey/<survey_id>` | GET | 生成问卷访问令牌 | 需登录 |
| `/change_password` | GET/POST | 修改个人密码 | 需登录 |

### 管理侧接口
| 端点 | 方法 | 描述 | 权限 |
|------|------|------|------|
| `/admin` | GET | 管理控制台 | 仅管理员 |
| `/admin/users` | GET | 用户管理 | 仅管理员 |
| `/admin/surveys` | GET | 问卷管理 | 仅管理员 |
| `/admin/config` | GET/POST | 系统配置 | 仅管理员 |

## 🔐 安全建议

1. **生产环境必须修改**：
   ```python
   app.secret_key = 'your-very-long-random-secret-key-here'
   ```

2. 启用HTTPS加密传输
3. 定期备份SQLite数据库
4. 修改所有默认密码（LimeSurvey、数据库、管理员账号）
5. 配置防火墙限制不必要的端口访问

## ❓ 常见问题

**Q: 为什么用户无法正常跳转到问卷？**
A: 请检查LimeSurvey API连接配置，确保URL、用户名和密码正确。

**Q: 如何批量创建用户？**
A: 使用管理员账号登录，进入"用户管理" → "批量导入"，上传CSV文件。

**Q: 系统支持哪些版本的LimeSurvey？**
A: 支持LimeSurvey 3.0及以上版本，需要启用RemoteControl API。

## 📝 更新日志

- **v1.0.0** (2025-08-20)
  - 初始版本发布
  - 实现基本用户认证功能
  - 集成LimeSurvey API令牌生成
  - 提供管理员管理界面

## 🤝 参与贡献

欢迎提交Issue和Pull Request来帮助改进SurveyGate项目。

## 📄 许可证

MIT License - 详见 LICENSE 文件。

---

**温馨提示**: 部署完成后，请务必测试所有功能是否正常，特别是LimeSurvey API连接和用户跳转流程。如遇问题，请查看Fl应用日志和Nginx错误日志进行排查。